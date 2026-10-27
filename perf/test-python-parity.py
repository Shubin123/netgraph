"""Compare native browser predictions/features against a local 802.class install.

Run with that project's Python environment:
python perf/test-python-parity.py /path/to/802.class
"""

import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    args = parser.parse_args()
    sys.path.insert(0, str(args.source.resolve()))
    import numpy as np
    from scapy.all import Dot11, Dot11FCS, Dot11QoS, RadioTap, Raw, wrpcap
    from infer.field_inference import infer_capture
    from wifi_app.capture import scope_pcap
    from wifi_app.contract import FEATURE_COLUMNS, feature_matrix, sessionize, window_sessions
    from wifi_app.training import aggregate_windows
    from sklearn.linear_model import LogisticRegression

    root = Path(__file__).resolve().parents[1]
    bssid, client = '02:00:00:00:00:01', '02:00:00:00:00:11'
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        for fcs in (False, True):
            packets = []
            for index in range(50):
                up = index % 2 == 0
                dot11 = Dot11FCS if fcs else Dot11
                packet = RadioTap(present='Flags+Rate+dBm_AntSignal', Flags=16 if fcs else 0, Rate=6, dBm_AntSignal=-42) / dot11(
                    type=2, subtype=8, FCfield=(0x41 if up else 0x42),
                    addr1=bssid if up else client, addr2=client if up else bssid,
                    addr3='02:00:00:00:00:aa', SC=((index + 1) % 4096) << 4,
                    ID=1234) / Dot11QoS(TID=3) / Raw(bytes([index]) * (96 + index % 7))
                packet.time = 100 + index * 0.05 + (20 if index >= 30 else 0)
                packets.append(packet)
            capture = directory / 'parity.pcap'
            wrpcap(str(capture), packets)
            scoped, _ = scope_pcap(capture, bssid)
            sessions, _ = sessionize(scoped, capture_id='parity')
            windows = list(window_sessions(sessions, window_size=16, stride=8, min_frames=8))
            matrices = np.asarray([feature_matrix(window, window_size=16) for window in windows], dtype=np.float32)
            valid = np.asarray([window.valid_frames for window in windows])
            aggregated = aggregate_windows(matrices, valid)
            for label_count in (2, 3):
                classifier = LogisticRegression(max_iter=2000).fit(aggregated, np.arange(len(aggregated)) % label_count)
                bundle = dict(kind='field-logistic-baseline-v1', schema_version='80211-metadata-v1',
                    feature_columns=list(FEATURE_COLUMNS),
                    window_size=16, labels=[f'class_{index}' for index in range(label_count)], classifier=classifier,
                    unknown_threshold=0.4, preprocessing=dict(min_frames=8, stride=8))
                import joblib
                checkpoint = directory / 'model.joblib'
                joblib.dump(bundle, checkpoint)
                model_json = directory / 'model.json'
                subprocess.run([sys.executable, str(root / 'scripts/export-browser-model.py'), str(checkpoint), str(model_json)], check=True, capture_output=True)
                expected = infer_capture(capture, bssid, bundle)
                javascript = """
const fs = require('node:fs');
const engine = require(process.argv[1]);
const model = JSON.parse(fs.readFileSync(process.argv[2]));
const bytes = fs.readFileSync(process.argv[3]);
const buffer = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
console.log(JSON.stringify(engine.infer(buffer, model, process.argv[4], 'parity')));
"""
                actual = json.loads(subprocess.check_output(['node', '-e', javascript, str(root / 'browser-inference.js'), str(model_json), str(capture), bssid], text=True))
                assert len(actual['sessions']) == len(expected['sessions'])
                assert len(actual['windows']) == len(expected['windows'])
                for observed, reference in zip(actual['windows'], expected['windows']):
                    for key in ('prediction', 'known_prediction', 'valid_frames', 'start_timestamp', 'end_timestamp'):
                        assert observed[key] == reference[key], (fcs, label_count, key, observed, reference)
                    assert abs(observed['confidence'] - reference['confidence']) < 1e-4, (observed, reference)
                for observed, reference in zip(actual['sessions'], expected['sessions']):
                    assert observed['prediction'] == reference['prediction']
                    assert observed['frames'] == reference['frames']
                print(f'Python parity passed: FCS={fcs}, classes={label_count}, windows={len(actual["windows"])}')


if __name__ == '__main__':
    main()
