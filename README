# Shodan Query Tool

* Pipe Shodan API results into a relational SQLite database
* Scrape Yelp.com to collect business website URLs 
* Query the SQLite database via command line, get the results in a .csv

### Prerequisites

- Python 3.x 
```
Pip is required to install additonal Python modules. Pip ships with Python 3.x
```

### Installing

- Install additional Python modules via pip
```
pip install -r requirements.txt
```

### Usage
qtool.py is used to interact with the program.
```
./qtool OPTIONS [QUERY] | [FILE]
    -q or --query: Query the database
    -f [FILE] or --file [FILE]: Query shodan.io API by specifying the path to a text file of queries
    -s or --shodan [QUERY]: Query shodan.io API with a single query, save the data in the database
    -y or --yelp: run the yelp web scraper
    -i or --import: search shodan.io API for gathered yelp hosts, results will be imported to shodan tables
    -h or --help: Display this 
```
**Querying the database**
```
./qtool.py -q
```
Select statements can now be entered, the results will be exported to a .csv file.
```
Type your Query Below to exit type 'exit'

select * from hosts

Output saved to: queries/25-06_11-26-16--905093.csv
```

## Acknowledgments

* cudeso, lines 162 - 164 of shodan_search.py were taken from "shodan-asset-monitor" https://github.com/cudeso/tools/blob/master/shodan-asset-monitor/shodan-asset-monitor.py
* Cliffe Schreuders for inspiration and guidance 
