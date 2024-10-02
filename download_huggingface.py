#!/usr/bin/env python3

import os
import argparse
import requests
import re



def get_files(url):
    try:
        # Send a GET request to the URL
        response = requests.get(url)
        # Check if the request was successful
        response.raise_for_status()  
        
        # Define a regex pattern to find href attributes
        href_pattern = r'href="(/[0-9\w\.\-_/]*)"'
        # Find all hrefs using the regex pattern
        hrefs = re.findall(href_pattern, response.text)
        
        return hrefs
    except requests.exceptions.HTTPError as http_err:
        print(f'HTTP error occurred: {http_err}')
    except Exception as err:
        print(f'Other error occurred: {err}')


huggingface = "https://huggingface.co/" 
def recursive_download(path, save_to):
  url_base = huggingface + path
  url = url_base + "?not-for-all-audiences=true"
  #print(url, save_to)
  hrefs = get_files(url)
    

  for href in hrefs:
    splited = href.split("/")
    if len(splited) < 4:
      continue
    if splited[3] == "tree" and len(href) - 1 > len(path):
      recursive_download("/".join(splited[1:]), save_to)
    if splited[3] == "blob":
      splited[3] = "resolve"
      download_path = "/".join(splited[1:])
      download_url = huggingface + download_path + "?download=true"
      local_path = save_to + "/" + "/".join(splited[5:])
      print(local_path)
      print("curl --create-dirs -L -C - \"" + download_url + "\" -o " + local_path)




if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="wye"
    )
    parser.add_argument(
        "repo", type=str, help="user/repo"
    )

    args = parser.parse_args()

    # Call the function with the provided command-line arguments
    path = args.repo + "/tree/main"
    recursive_download(
        path,
        args.repo.split("/")[1]
    )
