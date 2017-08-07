# -*- coding: utf-8 -*-
# for Python 3.4, 3.5
import geoip2.database as geodb
import geoip2.errors as geoerr

rec_city = geodb.Reader('GeoLite2-City.mmdb')
try:
    rec = rec_city.city("23.44.226.40")
    if rec:
        print(rec.country.iso_code)
        print(rec.country.names["ja"])
        print(rec.country.name)
        print(rec.city.names["ja"])
        print(rec.city.name)

except geoerr.AddressNotFoundError as anfe:
    print (anfe)

# 実行結果：
# US
# アメリカ合衆国
# United States
# ケンブリッジ
# Cambridge

# GeoLite2-City.mmdbは下記のURLからダウンロード
# https://dev.maxmind.com/ja/geolite2/
# Licenseは CC BY-SA 3.0
# 下記の文章を製品などに含むことでライセンスを満たすことになるようです。
# ===============================================================
# この製品には MaxMind が作成した GeoLite2 データが含まれており、
# <a href="http://www.maxmind.com">http://www.maxmind.com</a> から
# 入手いただけます。
# ===============================================================
