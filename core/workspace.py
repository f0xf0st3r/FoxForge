import os

class Workspacemanager:
    
    # make the folder workspaces
    
    def __init__(self, basedir = "workspace"):
        self.basedir = os.path.abspath(
            os.path.join(
                os.path.dirname(os.path.dirname(__file__)),
                basedir
            )
        )

        self.currentworkspace = None
        self.currentchallenge = None

        if not os.path.exists(self.basedir):
            os.makedirs(self.basedir, exist_ok=True)

    def setworkspace(self, challenge):
        self.currentchallenge = challenge
        self.currentworkspace = os.path.join(self.basedir,challenge)

        subfolders = ['logs', 'reports', 'scans', 'notes', 'extracted']


        if not os.path.exists(self.currentworkspace):
            os.makedirs(self.currentworkspace)
            
            for i in subfolders:
                os.makedirs(os.path.join(self.currentworkspace, i), exist_ok=True)
            
            print(f"workspace created successfully!! {self.currentworkspace}")
        
        else:
            print(f"error in creating workspace {self.currentworkspace}")

    def getdirpath(self, dirname):
        if not self.currentworkspace:
            return None
        return os.path.join(self.currentworkspace, dirname)
