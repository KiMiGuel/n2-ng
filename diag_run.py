"""Diagnosis harness: launch the real N2NgApp in demo mode without the
sudo re-exec or the click-to-close splash, so it can run inside a
systemd-run user-scope cage. Not part of the app; used for CPU diagnosis."""
import sys
import tkinter as tk

sys.path.insert(0, "src")

from n2ng.main import N2NgApp  # noqa: E402


def main():
    root = tk.Tk()
    app = N2NgApp(root, demo_mode=True)
    app.run()


if __name__ == "__main__":
    main()
