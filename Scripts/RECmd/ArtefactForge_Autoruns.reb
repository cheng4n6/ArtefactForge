Description: ArtefactForge supplement to Kroll_Batch - Run keys it does not cover
Author: ArtefactForge
Version: 1
Id: 9e9eb131-c1ee-403d-bb98-95204325a652
Keys:
#
# Kroll_Batch 1.22 reads the 64-bit SOFTWARE Run/RunOnce, the machine Policies\Explorer\Run and
# the per-user Run/RunOnce. These are the persistence locations it misses. Run as a second
# processor in RECmd_SystemHives and RECmd_NTUSER, writing to its own --csvf so the Kroll output
# is never overwritten. Drop an entry from here if a later Kroll_Batch adds it, or it reports twice.
#
# https://learn.microsoft.com/en-us/windows/win32/setupapi/run-and-runonce-registry-keys
# https://learn.microsoft.com/en-us/windows/win32/winprog64/registry-redirector

    -
        Description: Run (SOFTWARE, 32-bit)
        HiveType: SOFTWARE
        Category: Autoruns
        KeyPath: WOW6432Node\Microsoft\Windows\CurrentVersion\Run
        Recursive: false
        Comment: "32-bit programs run at any user logon; redirected here on 64-bit Windows"
    -
        Description: RunOnce (SOFTWARE, 32-bit)
        HiveType: SOFTWARE
        Category: Autoruns
        KeyPath: WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce
        Recursive: false
        Comment: "32-bit programs run once at the next logon, then deleted"
    -
        Description: Run (Group Policy, NTUSER)
        HiveType: NTUSER
        Category: Autoruns
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
        Recursive: false
        Comment: "Per-user policy Run key; writable by the user without admin rights"
