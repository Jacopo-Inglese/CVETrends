import os
import yaml
import time
import requests
from stix2 import Vulnerability
from stix2 import Bundle
from stix2 import Identity
from stix2 import ExternalReference
import json
from pycti import OpenCTIStix2Utils
from datetime import datetime
from pycti import OpenCTIConnectorHelper, get_config_variable



class Cve:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        # Extra config

    def get_interval(self):
        return int(1) * 60

   
    def convert(self, filename):
    # Create the default author
        
        PRE_LINK = "https://nvd.nist.gov/vuln/detail/"
    # count = 0
    # with open(filename) as json_file:
        vulnerabilities_bundle = []
        html = requests.get(filename).text
        data = json.loads(html)
        dati = data.get('data')
        for cves in dati:

            exter = PRE_LINK+cves.get('cve')
            name = cves.get('cve')
            cvssv3_base_score = cves.get('cvssv3_base_score')
            cvssv3_base_severity = cves.get('cvssv3_base_severity')
            description = cves.get('description')


        #Creo External referencs
            external_reference = ExternalReference(
                source_name="NIST NVD", url=exter
            )
            external_references=[external_reference]
            #prendo gli url di git
            github=cves.get('github_repos')
            for gitin in github:
                url=gitin.get('url')
                external_reference1 = ExternalReference(
                    source_name="Git hub",url=url
                )
                external_references.append(external_reference1)
            tweets=cves.get('tweets')
            for tweet in tweets:
                tweet_id=tweet.get('tweet_id')
                twitter_user_handle=tweet.get('twitter_user_handle')
                url="https://twitter.com/"+twitter_user_handle+"/status/"+tweet_id
                external_reference2= ExternalReference(
                    source_name="Tweet",url=url
                )
                external_references.append(external_reference2)
            reddit_posts=cves.get('reddit_posts')
            for reddit_post in reddit_posts:
                reddit_url=reddit_post.get('reddit_url')
                external_reference3 = ExternalReference(
                    source_name="Reddit", url=reddit_url
                )
                external_references.append(external_reference3)

        # Creating the vulnerability with the extracted fields
            vulnerability = Vulnerability(
            id=OpenCTIStix2Utils.generate_random_stix_id("vulnerability"),
            name=name,
            description=description,
            external_references=external_references,
                custom_properties={
                    "x_opencti_base_score":  cvssv3_base_score,
                    "x_opencti_base_severity": cvssv3_base_severity,

                },
                )
                # Adding the vulnerability to the list of vulnerabilities
            vulnerabilities_bundle.append(vulnerability)

    # Creating the bundle from the list of vulnerabilities
        bundle = Bundle(objects=vulnerabilities_bundle, allow_custom=True).serialize()
        return bundle

    def convert_and_send(self, url, work_id):
        try:



            # Converting the file to stix2
            self.helper.log_info("Converting the file")

            bundle = self.convert(url)

            self.helper.send_stix2_bundle(
                    bundle,
                    #entities_types=self.helper.connect_scope,
                    #update=True,
                    work_id=work_id,
            )
            # Remove files
           
        except Exception as e:
            
            self.helper.log_error(str(e))
            time.sleep(60)


    def process_data(self):

        try:
                timestamp = int(time.time())
                current_state = self.helper.get_state()

                if current_state is not None and "last_run" in current_state:
                    last_run = current_state["last_run"]
                    self.helper.log_info(
                            "Template last run: "
                            + datetime.utcfromtimestamp(last_run).strftime("%Y-%m-%d %H:%M:%S")
                    )
                else:
                    last_run = None
                    self.helper.log_info("Connector has never run")

                if last_run is None or ((timestamp - last_run) > ((int(self.ioctweet_interval) - 1) * 60 *60 )):
                    timestamp = int(time.time())
                    now = datetime.utcfromtimestamp(timestamp)
                    friendly_name = "Template run @ " + now.strftime("%Y-%m-%d %H:%M:%S")
                    work_id = self.helper.api.work.initiate_work(
                        self.helper.connect_id, friendly_name
                    )

                    self.helper.log_info(
                    f"Connector successfully run, storing last_run as {str(timestamp)}"
                    )
                    self.convert_and_send("https://cvetrends.com/api/cves/24hrs", work_id)
                    message = "Last_run stored"
                    self.helper.set_state({"last_run": timestamp})
                    self.helper.api.work.to_processed(work_id, message)
                    self.helper.log_info(message)
                else:
                    self.helper.log_info("Connector is not working")

        except Exception as e:
            self.helper.log_error(str(e))

    def run(self):
        self.helper.log_info("Fetching CVE knowledge...")
        if self.helper.get_run_and_terminate():
            self.process_data()
            self.helper.force_ping()
        else:
            while True:
                self.process_data()
                time.sleep(60*2)


if __name__ == "__main__":
    try:
        cveConnector = Cve()
        cveConnector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        exit(0)