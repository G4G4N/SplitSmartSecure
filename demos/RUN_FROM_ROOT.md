# Running Web UI Demos

## Important: Run from Project Root

Always run web UI demos from the **project root directory** (`SplitSmartSecure/`), not from the `demos/` directory.

## Correct Way

```bash
# From project root
cd SplitSmartSecure
python demos/web_demo_eavesdropping.py
```

## Why?

The demos need to:
1. Import modules from the parent directory
2. Access `web_app.py` to start the server
3. Access the `data/` directory for the database
4. Import shared modules correctly

## Quick Commands

```bash
# From project root (SplitSmartSecure/)
python demos/web_demo_eavesdropping.py      # Eavesdropping demo
python demos/web_demo_modification.py       # Modification demo
python demos/web_demo_analytics.py          # Analytics demo
python demos/web_demo_tampering.py          # Tampering demo
python demos/run_all_web_demos.py           # All demos
```

## If You Must Run from demos/

If you really need to run from the demos directory, use:

```bash
cd demos
python -m demos.web_demo_eavesdropping
```

But it's recommended to always run from the project root.

