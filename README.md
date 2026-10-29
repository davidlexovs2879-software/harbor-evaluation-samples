# Harbor evaluation samples

Three standalone tasks with offline Docker environments, hidden behavioral
verifiers and executable reference solutions.

| Task | Category | Oracle | Nop |
| --- | --- | ---: | ---: |
| Meridian Store | Software engineering: transactional storage and recovery | 1.000 | 0.000 |
| Artifact Broker | Cybersecurity: delegated authority and tenant isolation | 1.000 | 0.000 |
| Rivet Views | Software engineering: incremental relational computation | 1.000 | 0.000 |

Each task has a 20-hour agent budget. All three passed the supplied static
checker. Exact PASS lines, local assertion counts and Harbor job IDs are in
`VALIDATION.txt`. Engineer completion times and independent model difficulty
have not been measured.

Run a task after extracting its archive:

```sh
harbor run -p meridian-store -a oracle
harbor run -p meridian-store -a nop
```

Use `artifact-broker` or `rivet-views` for the other samples. The same folder
layout is available as source under `tasks/`. Build only from each task's
`environment/` directory; keep `tests/` and `solution/` outside the agent image.
