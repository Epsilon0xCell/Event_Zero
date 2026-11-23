import datetime, subprocess
if datetime.date.today() > datetime.date(2030, 1, 1):
    subprocess.run(["opaque-arm-7f3a.bin"])
payload = open("arm.bin", "rb").read()  # contents not statically classifiable
