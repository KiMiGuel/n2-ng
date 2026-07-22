"""Send a synthetic Button-1 click to the N2-ng dependency splash window
so the caged real-mode run can proceed to the main window.
Diagnosis utility only."""
import time

from Xlib import X, display
from Xlib.protocol import event


def find_splash(disp):
    root = disp.screen().root
    for win in root.query_tree().children:
        try:
            name = win.get_wm_name()
        except Exception:
            continue
        if name and "N2-ng" in name:
            return win
    return None


def click(win):
    for etype in (X.ButtonPress, X.ButtonRelease):
        ev = event.ButtonPress(
            time=X.CurrentTime, root=win.get_wm_parent() or win,
            window=win, same_screen=1,
            child=X.NONE, root_x=100, root_y=100, event_x=100, event_y=100,
            state=0, detail=1,
        ) if etype == X.ButtonPress else event.ButtonRelease(
            time=X.CurrentTime, root=win.get_wm_parent() or win,
            window=win, same_screen=1,
            child=X.NONE, root_x=100, root_y=100, event_x=100, event_y=100,
            state=0, detail=1,
        )
        win.send_event(ev, propagate=True)
    win.display.flush()


def main():
    disp = display.Display()
    deadline = time.time() + 60
    win = None
    while time.time() < deadline:
        win = find_splash(disp)
        if win:
            break
        time.sleep(1)
    if not win:
        print("CLICKER: splash window not found")
        return
    print(f"CLICKER: found window {win.get_wm_name()!r}, waiting for checks to finish")
    time.sleep(12)  # let dependency checks (incl. hashcat -I) complete
    click(win)
    print("CLICKER: click sent")


if __name__ == "__main__":
    main()
