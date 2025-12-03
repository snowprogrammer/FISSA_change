"""
## @Author : William PENSEC
## @Version : 0.0
## @Date : 14 février 2023
## @Description :
"""

### Import packages ###
import os
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import concurrent.futures
from datetime import datetime
from timeit import default_timer as timer

### Class ###
class AnalyseResults:
    """Analyses the results of simulations and manages the analysis in table or graph"""
    def __init__(self, data):
        self.__table_data = pd.DataFrame()
        self.__table_data_filtered = pd.DataFrame()
        self.__config = data
        self.__implem_version = self.__config['version']
        self.__idx_app = list()
        self.__table1 = self.__config['path_files_sim'] + "analyse/table_1/"
        if not os.path.exists(self.__table1):
        #     shutil.rmtree(self.__table1)
            os.makedirs(self.__table1)
        self.__table2 = self.__config['path_files_sim'] + "analyse/heatmap/"
        if not os.path.exists(self.__table2):
            # shutil.rmtree(self.__table2)
            os.makedirs(self.__table2)

    def get_codes(self):
        return self.__config['codes']

    def write_results(self, filename, data):
        try:
            with open(filename, 'w') as file:
                file.write(data)
        except Exception as e:
            print("An exception has occurred : {exc}".format(exc=e.args[1]))
            return 1
        return 0

    def table_res(self, appli: str, value: pd.DataFrame, t1: pd.DataFrame):
        """Display results in a table latex format"""
        total = len(value)
        self.__idx_app.append(appli)
        status_counts = value['status_end'].value_counts()

        # Extract counts for each status or set to 0 if not present
        crash = status_counts.get(1, 0)
        success = status_counts.get(2, 0)
        silence = status_counts.get(3, 0)
        detect = status_counts.get(4,0)

        # Calculate percentage of success
        percent_success = f'{(success / total) * 100:.2f}'

        # Update t1 DataFrame
        t1.loc[len(t1)] = [crash, success, silence, detect, f'{success} ({percent_success}\%)', total]


