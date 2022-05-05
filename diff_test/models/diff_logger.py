#!/usr/bin/env python3
# -*- coding: utf-8 -*-


# logging mechanism and hackish persistence 

import logging
import multiprocessing_logging

class Logger():
    def __init__(self):
        logging.basicConfig(filename="progress.log", level=logging.INFO)
        self.log = logging.getLogger()
        multiprocessing_logging.install_mp_handler(self.log)

    def info1(self, bin_name, bin_hash, mode, code ,msg):
        self.log.info(code + ":" + bin_name + ":" + bin_hash + ":" + mode + ":" + msg)

    def info2(self, bin_name, bin_hash, mode, mode2, code ,msg):
        self.log.info(code + ":" + bin_name + ":" + bin_hash + ":" + mode + ":" + mode2 + ":" + msg)
