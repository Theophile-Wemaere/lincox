import re

text = """
    Type: error-based
    Title: MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: &username=lincox' AND (SELECT 6705 FROM(SELECT COUNT(*),CONCAT(0x71716b6b71,(SELECT (ELT(6705=6705,1))),0x7171717171,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)-- SlaW&password=lincox&Login=lincox

        Type: time-based blind  <-- More indentation here
        Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
        Payload: &username=lincox' AND (SELECT 9477 FROM (SELECT(SLEEP(5)))SabE)-- arQL&password=lincox&Login=lincox

Type: UNION query  <-- No indentation here
Title: MySQL UNION query (NULL) - 8 columns
Payload: &username=lincox' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,CONCAT(0x71716b6b71,0x444a6e794f4d6d5868676b725564654961726e494c6a794446626f6a7845624965707463744a455a,0x7171717171),NULL,NULL#&password=lincox&Login=lincox

    Another random text
"""

pattern = r"""
    \s*Type:\s*(?P<type>.*)\n       # Handle leading whitespace
    \s*Title:\s*(?P<title>.*)\n      # Handle leading whitespace
    \s*Payload:\s*(?P<payload>.*)\n # Handle leading whitespace, "Another", and end of string
"""

matches = re.finditer(pattern, text, re.VERBOSE)

for match in matches:
    print("Type:", match.group("type"))
    print("Title:", match.group("title"))
    print("Payload:", match.group("payload").strip())
    print("-" * 20)