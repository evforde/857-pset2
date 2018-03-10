import requests
import json

IS_PROD = True
url = (
    "http://6857simon.csail.mit.edu/?num=10000" if IS_PROD else
    "http://127.0.0.1:3000/?num=10000"
)


def main():
    all_entries = json.load(open("./production-entries.json", "r")) or []
    for i in xrange(20):   # request 20 * 10,000 entries
        resp = requests.get(url)
        print("got resp " + str(i))
        data = json.loads(resp.content)
        all_entries.extend(data)
    f = open("./production-entries.json", "w")
    f.write(json.dumps(all_entries))


if __name__ == "__main__":
    main()
