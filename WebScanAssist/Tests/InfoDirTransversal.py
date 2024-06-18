# https://github.com/aels/subdirectories-discover/tree/main

from Classes.DataStorage import DataStorage
from Classes.ScanConfig import ScanConfig
from CustomImports import html_report


def t_dir_find(url):
    try:
        word_list = DataStorage.payloads('WORDS')
        for word in word_list:
            if url[-1] != '/':
                new_url = url + "/" + word
            else:
                new_url = url + word
            response = ScanConfig.session.get(new_url)
            if response.status_code == 200 and response.url != any(ds_url for ds_url in DataStorage.urls):
                html_report.add_hidden_path(new_url, response.status_code)
        return
    except UnicodeDecodeError:
        pass
    except Exception as e:
        print(e)
