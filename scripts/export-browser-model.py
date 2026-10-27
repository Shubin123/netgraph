#!/usr/bin/env python3
"""Export a trusted 802.class logistic baseline bundle for native browser inference."""

import argparse
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('checkpoint', type=Path, help='Trusted local field baseline .joblib bundle')
    parser.add_argument('output', type=Path, help='Destination model JSON')
    args = parser.parse_args()
    import joblib

    bundle = joblib.load(args.checkpoint)
    if bundle.get('kind') != 'field-logistic-baseline-v1':
        parser.error('Only field-logistic-baseline-v1 bundles are supported; TCN and legacy checkpoints are not.')
    if bundle.get('schema_version') != '80211-metadata-v1':
        parser.error('Unsupported feature schema.')
    classifier = bundle['classifier']
    classes = classifier.classes_.tolist()
    if classes != list(range(len(bundle['labels']))):
        parser.error('Classifier class indices do not match the labels.')
    model = {key: bundle[key] for key in ('kind', 'schema_version', 'feature_columns', 'window_size', 'labels')}
    model.update(
        classes=classes,
        coefficients=classifier.coef_.tolist(),
        intercepts=classifier.intercept_.tolist(),
        is_binary=len(classes) == 2 and len(classifier.coef_) == 1,
        preprocessing=bundle.get('preprocessing', {}),
        unknown_threshold=bundle.get('unknown_threshold', 0.0),
    )
    args.output.write_text(json.dumps(model, indent=2, allow_nan=False) + '\n', encoding='utf-8')
    print(f'Exported {len(classes)} labels to {args.output}')


if __name__ == '__main__':
    main()
