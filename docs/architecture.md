# ChronoNet architecture

ChronoNet intentionally uses a small dependency surface.

```text
Browser dashboard
      |
      | HTTP / JSON
      v
Python ThreadingHTTPServer
      |
      +--> scenario loader --> JSON incident fixtures
      |
      +--> correlation engine --> findings + confidence + evidence
      |
      +--> report builder --> Markdown incident report
```

## Design goals

- **Portable:** one Python command on Windows, Linux, or macOS.
- **Explainable:** every finding includes evidence, confidence, and a recommended next check.
- **Safe by default:** no active scanning or packet capture.
- **Testable:** correlation logic is isolated from the HTTP/UI layer.
- **Extensible:** new scenarios are JSON files and new detectors are small Python rules.
