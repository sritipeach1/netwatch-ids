# NetWatch on CIC-IDS2017

Flow classifier trained and evaluated on real captured traffic from CIC-IDS2017 (2,830,743 flows, 56,301 per-source 60-second windows).

## Method

- Features: NetWatch's 11 behaviour features per source over 60-second windows, windows with at least 3 flows.
- Classes: benign, port scan, brute force (FTP/SSH-Patator), DoS/flood (DoS Hulk, GoldenEye, slowloris, Slowhttptest, DDoS). Web attacks, bots, infiltration and Heartbleed are left out (608 windows): they are signature-rule territory.
- Evaluation: 5-fold cross-validation grouped by 10-minute time blocks. Every figure below comes from out-of-fold predictions.
- Decision rule: as deployed, a window is flagged when 1 - P(benign) >= 0.8.

## Results

| Metric | Value |
| --- | --- |
| Macro F1 (4 classes) | 0.815 ± 0.101 |
| Attack detection recall | 71.1% |
| Detection precision | 100.0% |
| False alarm rate (benign windows flagged) | 0.00% (0 of 56,059) |

### Per class

| Class | Precision | Recall | F1 | Windows |
| --- | --- | --- | --- | --- |
| Benign | 99.9% | 100.0% | 0.999 | 56,059 |
| Brute force | 100.0% | 90.4% | 0.950 | 125 |
| DoS / flood | 100.0% | 56.2% | 0.720 | 96 |
| Port scan | 100.0% | 23.8% | 0.385 | 21 |

### Per attack

| Attack | Windows | Detected | Correct type |
| --- | --- | --- | --- |
| SSH-Patator | 63 | 88.9% | 88.9% |
| FTP-Patator | 62 | 91.9% | 91.9% |
| DoS slowloris | 26 | 42.3% | 42.3% |
| DDoS | 22 | 86.4% | 86.4% |
| DoS Hulk | 21 | 76.2% | 76.2% |
| PortScan | 21 | 23.8% | 23.8% |
| DoS Slowhttptest | 19 | 26.3% | 26.3% |
| DoS GoldenEye | 8 | 37.5% | 37.5% |

## Does the simulator-trained model transfer?

The model the demo uses was trained only on simulated traffic. Scored on the same real windows:

| | Simulator model | Retrained on CIC-IDS2017 |
| --- | --- | --- |
| Attack detection recall | 1.7% | 71.1% |
| False alarm rate | 1.48% | 0.00% |

## Caveats

- CIC-IDS2017 is a lab capture from 2017 with known labelling errors (Engelen et al., 2021). Results are a benchmark, not a promise for any particular network.
- Each attack type ran on a single day from a small set of machines, so time-block cross-validation tests unseen stretches of each attack, not unseen attackers.
- CICFlowMeter byte counts are payload bytes; Suricata counts whole packets. The live sensor needs this model retrained on its own flow records before it is used there.
- Most original files carry minute-level timestamps. For those, flow rate is counted over the full 60-second window.

Generated 2026-11-26 by `python -m app.train_cicids`.
