'''
Description: 
version: 
Author: zlx
Date: 2023-12-16 21:54:12
LastEditors: zlx
LastEditTime: 2023-12-17 15:37:00
'''
import scrapy
import csv

'''
爬取tshark提供文档能够提取的字段信息
'''
def tshark_doc_crawler_save(response, csv_name):
    # 使用XPath选择器提取所有tr标签
    tr_tags = response.xpath('//tr')

    # 创建CSV文件并写入表头
    with open("./fields/" + csv_name, "w", newline="") as csvfile:
        writer = csv.writer(csvfile, delimiter=",")
        writer.writerow(["Field_name", "Description", "	Type", "Versions"])  # 列名
        # 遍历每个tr标签，并将三个td标签的内容写入CSV文件
        for tr in tr_tags:
            td_tags = tr.xpath(".//td")
            # print(len(td_tags))
            if len(td_tags) == 4:
                # 提取4个td标签的内容
                text = td_tags.xpath("string()").get()  # 提取<td>标签内的所有文本内容
                strings = text.split("<wbr>")  # 使用<wbr>分割字符串
                column1 = ''.join(strings)  # 连接三个字符串
                print(column1)  # 输出连接后的结果

                column2 = td_tags[1].xpath("./text()").get()
                column3 = td_tags[2].xpath("./text()").get()
                column4 = td_tags[3].xpath("./text()").get()

                # 写入CSV文件
                writer.writerow([column1, column2, column3, column4])
    return


class MySpider(scrapy.Spider):
    name = "crawler"
    start_urls = ["https://www.wireshark.org/docs/dfref/t/tls.html", 
                  "https://www.wireshark.org/docs/dfref/t/tcp.html",
                  "https://www.wireshark.org/docs/dfref/d/dns.html"]

    def parse(self, response):
        if response.url == "https://www.wireshark.org/docs/dfref/t/tls.html":
            tshark_doc_crawler_save(response, "tls.csv")
        elif response.url == "https://www.wireshark.org/docs/dfref/t/tcp.html":
            tshark_doc_crawler_save(response, "tcp.csv")
        elif response.url == "https://www.wireshark.org/docs/dfref/d/dns.html":
            tshark_doc_crawler_save(response, "dns.csv")
        else:
            self.logger.info("Unsupported URL: %s" % response.url)
