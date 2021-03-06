from sys import argv
from database import query_input, yelp_to_shodan
from scraper import yelp_result_scraper
from shodan_search import search, query_file_parser


def help():
    print(
        '''
    Usage: ./qtool OPTIONS [QUERY] | [FILE]
    Options:
    -q or --query: Query the database
    -f [FILE] or --file [FILE]: Query shodan.io API by specifying the path to\
 a text file of queries
    -s or --shodan [QUERY]: Query shodan.io API with a single query,\
 save the data in the database
    -y or --yelp: run the yelp web scraper
    -i or --import: search shodan.io API for gathered yelp hosts,\
 results will be imported to shodan tables
    -h or --help: Display this message
    ''')


if len(argv) > 1:
    argument = argv[1]
else:
    help()
    exit()

if argument == '-q' or argument == '--query':
    query_input()

elif '-f' in argument or '--file' in argument:
    file_path = argv[2]
    query_file_parser(file_path)

elif argument == '-s' or argument == '--shodan':
    try:
        query = argv[2]
        search(query)
    except IndexError:
        print('\nError: Please provide a Shodan search query\n')
        exit()

elif argument == '-y' or argument == '--yelp':
    yelp_result_scraper()

elif argument == '-i' or argument == '--import':
    yelp_to_shodan()

elif argument == '-h' or argument == '--help':
    help()
