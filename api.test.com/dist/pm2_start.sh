#!/bin/bash
set NODE_ENV = production
pm2 delete index
pm2 start index.js
