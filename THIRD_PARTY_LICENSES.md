# Third-party software

The files in `frontend/vendor/` are unmodified builds of the following libraries.
They are distributed under their own licenses, not under the MIT license of this project.

| File | Library | Version | License | Source |
|---|---|---|---|---|
| `react.production.min.js` | React | 18.3.1 | MIT, © Meta Platforms, Inc. and affiliates | https://github.com/facebook/react |
| `react-dom.production.min.js` | React DOM | 18.3.1 | MIT, © Meta Platforms, Inc. and affiliates | https://github.com/facebook/react |
| `htm.umd.js` | htm | 3.1.1 | Apache License 2.0, © Google LLC | https://github.com/developit/htm |
| `chart.umd.js` | Chart.js | 4.4.1 | MIT, © Chart.js Contributors | https://github.com/chartjs/Chart.js |

Full license texts:
- MIT: https://opensource.org/license/mit
- Apache License 2.0: https://www.apache.org/licenses/LICENSE-2.0

## Data sources

The dashboard downloads public threat feeds at runtime (see the Threat-Feeds tab and the README).
They are not part of this repository and each comes with its own terms of use; for example
Spamhaus DROP may only be used non-commercially or at small scale.
