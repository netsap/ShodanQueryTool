from sys import argv
from database import query_input, import_yelp_data, yelp_to_shodan
from scraper import page_scraper
from shodan_search import search, file_parser


def help():
    print(
        '''
    Usage: ./query_tool OPTIONS [QUERY]
    
    Options:
    -q or --query: Query the database
    -f [FILE] or --file [FILE]: Query shodan.io API by specifying the path to a text file of queries
    -s or --shodan [QUERY]: Query shodan.io API with a single query, save the data in the database
    -y or --yelp: run the yelp web scraper
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
    file_parser(file_path)

elif argument == '-y' or argument == '--yelp':
    page_scraper()

elif argument == '-i' or argument == '--import':
    yelp_to_shodan()

elif argument == '-s' or argument == '--shodan':
    try:
        query = argv[2]
        search(query)
    except IndexError:
        print('\nError: Please provide a Shodan search query\n')
        exit()

elif argument == '-h' or argument == '--help':
    help()
