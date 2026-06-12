import os
from datetime import datetime

class Logs:
    def __init__(self, overalllogs='logs'):
        self.overalllogs = os.path.abspath(
            os.path.join(os.path.dirname(
                os.path.dirname(__file__)
            ), overalllogs)
        )
        if not os.path.exists(self.overalllogs):
            os.makedirs(self.overalllogs, exist_ok=True)

        self.overalllogfile = os.path.join(self.overalllogs, 'OverallLogs.log')


    def logexe(self, command, status, outputfile, workspacelogsfolder = False):
        time = datetime.now()
        entry = f"time : {time}\n command : {command}\n status : {status}\n output file : {outputfile}"

        with open(self.overalllogfile, "a") as f:
            f.write(entry)

        
        if workspacelogsfolder:
            workspacelogs = os.path.join(workspacelogsfolder,"execution.log")
            with open(workspacelogs, "a") as f:
                f.write(entry)