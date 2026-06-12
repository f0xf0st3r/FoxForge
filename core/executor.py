import subprocess 
# for running terminal commands in python

import os

class Executor:
    def __init__(self, logs, workspace):
        self.logs = logs
        self.workspace = workspace

    def run(self, command, outputdir = "scans", outputfilename = None):
        print(f"executing {command}")

        outputpath = None
        workspacelogs = None

        if self.workspace.currentworkspace:
            workspacelogs = self.workspace.getdirpath("logs")
            if outputfilename:
                outputpath = os.path.join(self.workspace.getdirpath(outputdir), outputfilename)

        status = 'SUCCESS'
        output = ""
        try:
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True
            )

            for i in process.stdout:
                print(i, end="")
                output += i
                
            process.wait()

            if process.returncode != 0:
                print("error in executing the command try again...")
                status = 'ERROR'
        
        except Exception as e:
            status = 'ERROR'
            output = f"An unexpected error occurred: {str(e)}"
            print(output)

        
        if outputpath and output:
            try:
                with open(outputpath, "w") as f:
                    f.write(output)
                print(f"output saved to {outputfilename}")
            except Exception as e:
                print("error saving in output file")

        self.logs.logexe(command, status, outputpath, workspacelogs)

