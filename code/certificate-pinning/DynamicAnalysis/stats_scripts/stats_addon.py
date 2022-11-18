from collections import defaultdict
from mitmproxy import ctx
import pickle
import sys
import json
import re
import hashlib
import os

class DumpFilter:
    def __init__(self):
        self.startup = False
        self.pack_hash = ""
        self.past_pinned_domains = set()
        self.urls = defaultdict(int)
        self.request_set = defaultdict(set)
        self.request_coutner = defaultdict(int)
        self.piilog = defaultdict(set)

    def load(self, loader):
        loader.add_option(
                name     = "pii",
                typespec = str,
                default  = '',
                help     = "PII to grep text and request body for. Separated by a newline.",)
        loader.add_option(
                name     = "results",
                typespec = str,
                default  = '',
                help     = "File to write final stats to.",)
        loader.add_option(
                name     = "failedhandshakes",
                typespec = str,
                default  = '',
                help     = "File to write final stats to.",)

    def startupCheck(self):
        # Weird hack cause lifecycle doesn't load and then trigger a function :/
        # Load some default files, at the start of processing all packets
        if not self.startup:
            self.pack_hash = ctx.options.rfile.split("/")[-1][:-5]
            self.startup = True
            # Only load this if we're not writing
            try:
                with open(ctx.options.pii, "r") as infile:
                    self.pii = json.load(infile)
                with open(ctx.options.failedhandshakes, "r") as infile:
                    failedhandshakes = json.load(infile)
                    if self.pack_hash in failedhandshakes:
                        if "failed_handshakes" in failedhandshakes[self.pack_hash]:
                            for ip, domains in failedhandshakes[self.pack_hash]["failed_handshakes"].items():
                                self.past_pinned_domains.update(domains)
            except FileNotFoundError:
                ctx.log.info("Invalid PII file supplied :/")
            except json.decoder.JSONDecodeError:
                ctx.log.info("Invalid PII/Domain json file :/")

    def request(self, flow):
        self.startupCheck()
        # Count urls being hit
        current_domain = self.getUrl(flow.request.pretty_url)
        if current_domain not in self.past_pinned_domains:
            return
        self.urls[flow.request.pretty_url] += 1
        self.request_set[current_domain].add(flow.request.text)
        self.request_coutner[current_domain] += 1
        ctx.log.info(flow.request.text)
        # Assuming our baseline is well curated to only contact legit domains.
        try:
            for pik in self.pii.keys():
                # Try to decode the content
                result, extras = self.advanceSearch(pik, flow)
                if result:
                    self.piilog[pik].add(current_domain)
        except ValueError as e:
            ctx.log.info("Value error fetching request text.")

    def done(self):
        print("Domains that were previously pinned:", self.past_pinned_domains)
        for domain, requests in self.request_coutner.items():
            print("Domain:", domain, "# Requests:", requests)
        self.writeResults()

    def advanceSearch(self, string, flow):
        # Does a bunch of things to string and searches for it in the flow.
        found = False
        retlst = []
        smd5 = hashlib.md5(string.encode()).hexdigest()
        ss1 = hashlib.sha1(string.encode()).hexdigest()
        ss224 = hashlib.sha224(string.encode()).hexdigest()
        ss256 = hashlib.sha256(string.encode()).hexdigest()
        if (re.search(string, flow.request.text, re.IGNORECASE) or re.search(string, flow.request.pretty_url, re.IGNORECASE)):
            found = True
            retlst.append("")
        elif (re.search(smd5, flow.request.text, re.IGNORECASE) or re.search(smd5, flow.request.pretty_url, re.IGNORECASE)):
            found = True
            retlst.append("") # Ignore extra info for now
        elif (re.search(ss1, flow.request.text, re.IGNORECASE) or re.search(ss1, flow.request.pretty_url, re.IGNORECASE)):
            found = True
            retlst.append("")
        elif (re.search(ss224, flow.request.text, re.IGNORECASE) or re.search(ss224, flow.request.pretty_url, re.IGNORECASE)):
            found = True
            retlst.append("") # Ignore extra info for now
        elif (re.search(ss256, flow.request.text, re.IGNORECASE) or re.search(ss256, flow.request.pretty_url, re.IGNORECASE)):
            found = True
            retlst.append("") # Ignore extra info for now
        if ":" in string or "-" in string:
            string = string.replace(":", "")
            string = string.replace("-", "")
            res1, res2 = self.advanceSearch(string, flow)
            retlst.extend(res2)
            return (found | res1), retlst
        return found, retlst

    def getUrl(self, s):
        return s.split("/")[2]

    def serialize_sets(self, obj):
        if isinstance(obj, set):
            return list(obj)
        return obj

    def writeResults(self):
        # Write all stats we collect.
        pack_hash = ctx.options.rfile.split("/")[-1][:-5]
        current_results = {}
        try:
            with open(ctx.options.results, "r") as infile:
                current_results = json.load(infile)
        except json.decoder.JSONDecodeError:
            print("Invalid json found at: " + ctx.options.uploadfile + ", continuing...")
        except FileNotFoundError:
            print("File", ctx.options.results, "not found, will create it and write...")
        if pack_hash in current_results:
            print("Result already exists!! Will be overwritten...")
        to_write = {}
        to_write["all_requests"] = list(self.urls.keys())
        to_write["request_set"] = self.request_set
        if len(self.piilog) > 0:
            to_write["pii_log"] = {k: list(v) for k, v in self.piilog.items()}
        current_results[pack_hash] = to_write
        with open(ctx.options.results, "w+") as outfile:
            try:
                json.dump(current_results, fp=outfile, sort_keys=True, indent=2,
                    default=self.serialize_sets)
            except:
                print("Error dumping json to results file :/")
        print("Done writing results", pack_hash, "to", ctx.options.results)

addons = [DumpFilter()]
