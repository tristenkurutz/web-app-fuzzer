from urllib.parse import urljoin, urlparse

import mechanicalsoup
import argparse

from mechanicalsoup import LinkNotFoundError


# Tristen Kurutz
# SWEN-331, October 2024
def set_arg():
    """
    Sets up the command line arguments and commands for the Fuzzer application.  Reads in the input and runs specific
    functions based on the combination of arguments and commands.
    """
    parser = argparse.ArgumentParser()

    subparsers = parser.add_subparsers(dest="command")
    discover_parser = subparsers.add_parser("discover",
                                            help="Output a comprehensive, human-readable list of all discovered inputs "
                                                 "to the system. Techniques include both crawling and guessing.")
    discover_parser.add_argument("url", help="Input destination URL", type=str)

    discover_parser.add_argument("--custom-auth",
                                 help="--custom-auth=string : Signal that the fuzzer should use hard-coded "
                                      "authentication for a specific application (e.g. dvwa).",
                                 type=str)
    discover_parser.add_argument("--common-words",
                                 help="--common-words=string : Define where the common word guesser text file is.",
                                 type=str,
                                 required=True)

    discover_parser.add_argument("--vectors",
                                 help="--vectors=string : Define where the vectors text file is.",
                                 type=str,
                                 required=False)

    discover_parser.add_argument("--sensitive",
                                 help="--sensitive=string : Define where the sensitive data text file is.",
                                 type=str,
                                 required=False)

    discover_parser.add_argument("--sanitized-chars",
                                 help="--sensitive=string : Define the file path of characters separated by new lines "
                                      "to test to determine whether an input has been sanitized.",
                                 type=str,
                                 required=False)

    args = parser.parse_args()

    browser_instance = mechanicalsoup.StatefulBrowser(user_agent='MechanicalSoup')

    # Checks for required arguments to run 'discover'
    if args.command == "discover" and args.url and args.common_words:
        connect_auth(args.custom_auth, args.url, browser_instance)
        vectors, sensitive, chars = read_in_processing_files(args.vectors, args.sensitive, args.sanitized_chars)
        discovery(args.url, browser_instance, args.common_words, vectors, sensitive, chars)

    # Just logging in is also a valid combination
    elif args.custom_auth and args.url:
        connect_auth(args.custom_auth, args.url, browser_instance)


def connect_auth(auth_type, url, browser_instance):
    """
    Logs the client into the admin account using the DVWA credentials.
    :param auth_type: Type of application to log into
    :param url: The current base URL
    :param browser_instance: The browser that is currently open
    :return:
    """

    # This assignment only required DVWA login, therefore, this is the only case
    if auth_type == "dvwa":
        browser_instance.open(url + "/setup.php")
        browser_instance.select_form('form[action="#"]')
        browser_instance.submit_selected()

        browser_instance.open(url)
        browser_instance.select_form('form[action="login.php"]')
        browser_instance["username"] = "admin"
        browser_instance["password"] = "password"
        browser_instance.submit_selected()

        browser_instance.open(url + "/security.php")
        browser_instance.select_form('form[action="#"]')
        browser_instance["security"] = "Low"
        print("CHANGING SECURITY TO LOW\n")

        browser_instance.submit_selected()

        browser_instance.open(url)


def join_url(base_url, tag):
    """
    Custom URL join function that handles edge cases where the tag does not have a leading slash.

    :param base_url: The plain base URL provided by the user
    :param tag: The href tag's link found inside the HTML
    :return: The joined URL, or None if the tag is an external URL.
    """

    if not base_url:
        return tag
    if not tag:
        return base_url

    if tag.startswith('/'):
        tag = tag.split('/', maxsplit=1)
        tag = ''.join(tag[1:])

    # Check if the tag is a full URL
    if tag.startswith("http:") or tag.startswith("https:"):
        # Only return the tag if the base_url is an internal link
        if base_url in tag:
            return tag
        # Return None for external URLs
        return None

    # Handle relative paths
    if tag.startswith('.'):
        tag = tag.lstrip('./')

    if not base_url.endswith('/'):
        base_url += '/'

    return base_url + tag


def common_link_discover(url, browser_instance, file_path_word):
    """
    Takes a text file input with different words and extensions to guess and append onto the base URL
    and compiles the guessed links that work.

    :param url: The current base URL
    :param browser_instance: The browser that is currently open
    :param file_path_word: The location of the word guesser input
    :return: The links guessed correctly
    """
    links = []
    exts = []
    reader = open(file_path_word)

    try:
        words = reader.readlines()
        stripped_words = []
        for word in words:
            string = word.strip('\n')

            split = string.split(".")
            # Split the input into the word and its extension, so we can try different combinations.
            new_word = split[0]
            ext = split[1]
            stripped_words.append(new_word)
            exts.append(ext)

        for word in stripped_words:
            for extension in exts:
                appended_url = url + '/' + word
                response = browser_instance.open(appended_url)

                # If the response is OK, then we know we discovered a link.
                if response.status_code == 200:
                    links.append(appended_url)

                # Try combinations of words and extensions.
                appended_url_ext = url + '/' + word + "." + extension
                response = browser_instance.open(appended_url_ext)
                if response.status_code == 200 and appended_url_ext not in links:
                    links.append(appended_url_ext)

        links.append(url)
    finally:
        reader.close()

    return links


def input_guess_link(current_url):
    """
    Guesses input fields based on the parameters in a link.
    :param current_url: The current URL to analyze
    """
    parsed_url = urlparse(current_url)
    query_string = parsed_url.query

    # Splits the links into its parameters
    if query_string:
        queries = query_string.split("&")
        parameters = {key: value for key, value in (pair.split("=") for pair in queries)}
        print_input_guess("URL", parameters)


def input_guess_html(browser_instance, current_url):
    """
    Guesses input fields based on the HTML in a page.
    :param browser_instance: The current browser open
    :param current_url: The current URL to analyze
    """
    browser_instance.open(current_url)
    # Searches for any element in the page with the "input" field
    inputs = browser_instance.page.select("input")

    # Grabs the name and the value of the input field
    inputs_data = {input.get("name", ""): input.get("value", "") for input in inputs}

    # Print out what we discovered.
    print_input_guess("HTML", inputs_data)


def input_guess_cookie(browser_instance, current_url):
    """
    Guesses input fields based on the cookies in a page.
    :param browser_instance: The current browser open
    :param current_url: The current URL to analyze
    """
    browser_instance.open(current_url)

    # Grab the cookies in the current session.
    cookies = {cookie.name: cookie.value for cookie in browser_instance.session.cookies}

    # Print out what we discovered.
    print_input_guess("COOKIE", cookies)


def print_input_guess(name, input_data):
    """
    A streamlined way to print the input guesses of all kinds.
    :param name: The name of the guess method
    :param input_data: The data gathered from the guess
    """
    if input_data:
        print(name + " INPUTS:")
        print("********************************************")
        print("*          Name           *     Value      *")
        print("********************************************")
        for key, value in input_data.items():
            print("*" + key.center(24) + "*" + value.center(16) + "*")
        print("********************************************\n")
    else:
        print(name + " INPUTS:")
        print("********************************************")
        print("None.")
        print("********************************************\n")


def search_node(url, current_node, browser_instance, queue, processed):
    """
    Searches a webpage node and gathers all of its children, aka links inside it.
    :param url: The base URL
    :param current_node: The current tag to append to the base URL to analyze
    :param browser_instance: The current open browser
    :param queue: The queue structure to process nodes in
    :param processed: The array that keeps track of which nodes have already been searched
    :return: The links that have been discovered from the current node
    """
    browser_instance.open(current_node)

    # Make sure that the current node is a valid URL and can open (sanity check)
    if browser_instance.page is not None:
        # Get all the links on the page, hyperlinks using href
        discovered_tags = browser_instance.links()
        discovered_links = []
        conv_url = None
        for tag in discovered_tags:
            href_got = tag.get('href')
            if not href_got.startswith("http://") or not href_got.startswith("https://"):
                href_got = '/' + href_got
                conv_url = join_url(url, href_got)

            if conv_url:
                # We do not want to log out and ruin our algorithm
                if conv_url.endswith("logout.php"):
                    break

                # Prevents duplicates
                if conv_url.startswith("http://") or conv_url.startswith("https://"):
                    if url in conv_url:
                        discovered_links.append(conv_url)
                        queue.append(conv_url)
                elif conv_url:
                    new_conv_url = url + conv_url
                    discovered_links.append(new_conv_url)
                    if new_conv_url not in processed:
                        queue.append(new_conv_url)
        return discovered_links


def discovery(url, browser_instance, word_file_path, vector_array, sensitive_array, sanitized_chars):
    """
    Searches all nodes possible from the starting node for new links.
    :param url: The base URL
    :param browser_instance: The current open browser
    :param word_file_path: The path to the word file
    :param vector_array: The array of vectors processed from its text file
    :param sensitive_array: The array of sensitive data to search for processed from its text file
    :param sanitized_chars: The array of sanitized characters to input processed from its text file
    """

    # Initialize counters

    num_injections = 0
    num_sensitive = 0
    num_bad_responses = 0
    num_dos = 0
    num_sani = 0

    links = common_link_discover(url, browser_instance, word_file_path)
    queue = []
    processed = set()

    for link in links:
        search_node(url, link, browser_instance, queue, processed)
        processed.add(link)

        while len(queue) != 0:
            current_link = queue.pop(0)
            if current_link not in processed:
                child_links = search_node(url, current_link, browser_instance, queue, processed)

                if child_links is None:
                    break

                # Process children
                for linky in child_links:
                    if linky not in processed:
                        search_node(url, linky, browser_instance, queue, processed)

                    # Process grandchildren
                    for new_node in child_links:
                        if new_node not in processed:
                            queue.append(new_node)

            processed.add(current_link)

    print("Links Discovered ", "(", len(processed), ")")
    print("********************************************")
    for found in processed:
        print(found)

    print("\nLinks Guessed", "(", len(links), ")")
    print("********************************************")
    for common in links:
        print(common)
    print("************************************************")

    for found in processed:
        print("PAGE: ", found)
        print("********************************************")

        # Guessing based on link, HTML, cookies
        input_guess_link(found)
        input_guess_html(browser_instance, found)
        input_data = form_processing(browser_instance)

        # If there is a form with input fields, then check the form for vulnerabilities
        if input_data:
            injections, sensitives, bad_responses, dos_count, san_in = form_check(browser_instance, input_data,
                                                                                  vector_array,
                                                                                  sensitive_array, sanitized_chars)
            num_injections += injections
            num_sensitive += sensitives
            num_bad_responses += bad_responses
            num_dos += dos_count
            num_sani += san_in

        input_guess_cookie(browser_instance, found)

    # We do not want to print anything if no array was given to test with.
    if vector_array:
        print("\nNumber of possible SQL injections: ", num_injections, '\n')
        print("Number of possible bad responses: ", num_bad_responses, '\n')
        print("Number of possible DOS vulnerabilities: ", num_dos, '\n')

    if sensitive_array:
        print("Number of possible sensitive data leaks: ", num_sensitive, '\n')

    if sanitized_chars:
        print("Number of possible unsanitized inputs: ", num_sani, '\n')


def read_in_processing_files(vector_file_path, sensitive_file_path, sanitized_file_path):
    """
    Helper function that processes files into arrays.
    :param vector_file_path: The file path to the vector text file
    :param sensitive_file_path: The file path to the sensitive data text file
    :param sanitized_file_path: The file path to the sanitized character text file
    :return: The arrays processed from the text files
    """
    stripped_vectors = []
    stripped_sensitive_data = []
    stripped_sanitized = []

    try:
        if sensitive_file_path:
            reader = open(sensitive_file_path)
            sensitive_data = reader.readlines()
            for data in sensitive_data:
                string = data.strip('\n')
                stripped_sensitive_data.append(string)
            reader.close()

        if vector_file_path:
            reader = open(vector_file_path)
            vectors = reader.readlines()
            for vector in vectors:
                string = vector.strip('\n')
                stripped_vectors.append(string)
            reader.close()

        if sanitized_file_path:
            reader = open(sanitized_file_path)
            sanitized_array = reader.readlines()
            for data in sanitized_array:
                string = data.strip('\n')
                stripped_sanitized.append(string)
            reader.close()

    finally:
        return stripped_vectors, stripped_sensitive_data, stripped_sanitized


def form_processing(browser_instance):
    """
    Selects a form on a page and discovers all of its input boxes.
    Feeds the name of the input field and its current value into a dictionary.
    :param browser_instance: The current browser open
    :return: A dictionary of input data.
    """
    try:
        form = browser_instance.select_form('form')
        input_fields = form.form.find_all('input')
        inputs_data = {}

        for input_field in input_fields:
            name = input_field.get("name", "")
            value = input_field.get("value", "")

            # Sanity check to make sure that all values are empty rather than null
            if name:
                inputs_data[name] = value if value is not None else ""

        return inputs_data

    except LinkNotFoundError:
        print("No form found.")


def form_check(browser_instance, inputs_data, vector_array, sensitive_array, sanitized_chars):
    """
    Checks a form for different vulnerabilities.
    :param browser_instance: The current browser
    :param inputs_data: The inputs processed inside the form
    :param vector_array: The array of vectors to try inside the input fields
    :param sensitive_array: The array of sensitive data to check responses for
    :param sanitized_chars: The array of sanitized characters to try inside the input fields
    :return:
    """
    sql_injection_num = 0
    sensitive_data_leak_num = 0
    bad_response_num = 0
    dos_num = 0
    san_num = 0

    for name in inputs_data:
        if vector_array:
            for vector in vector_array:
                try:
                    form = browser_instance.select_form('form')
                    input_field = form.form.find('input', {'name': name})

                    # Skip any input field that is asking for a file path, it breaks the algorithm.
                    if input_field and input_field.get('type') != 'file':
                        form.set(name, vector)
                        response = browser_instance.submit_selected()

                        # If the response code is anything other than 200, then it's bad and can be a vulnerability.
                        if response.status_code != 200:
                            bad_response_num += 1

                        # If the response takes any longer than 20 seconds, potentially DOS.
                        if response.elapsed.total_seconds() > 20:
                            dos_num += 1

                        string = str(response.content)

                        # Lowercase to consider all different capitalizations of data.
                        string = string.lower()

                        if string.find("error in your sql syntax") >= 0 or string.find("sql error") >= 0:
                            sql_injection_num += 1

                        for data in sensitive_array:
                            data = data.lower()
                            if string.find(data) >= 0:
                                sensitive_data_leak_num += 1

                except LinkNotFoundError:
                    print("No form found.")
        if sanitized_chars:
            for char in sanitized_chars:
                try:
                    form = browser_instance.select_form('form')
                    char_agg = 'foobar' + char + 'foobar'
                    input_field = form.form.find('input', {'name': name})

                    # Skip any input field that is asking for a file path, it breaks the algorithm.
                    if input_field and input_field.get('type') != 'file':
                        form.set(name, char_agg)
                        response = browser_instance.submit_selected()
                        string = str(response.content)

                        # If we find the input character inside the response content, we know it didn't properly
                        # filter it out.
                        if string.find(char_agg):
                            san_num += 1
                            break
                except LinkNotFoundError:
                    print("No form found.")
        else:
            try:
                # Default case for when no sanitization characters are given.
                form = browser_instance.select_form('form')
                input_field = form.form.find('input', {'name': name})

                # Skip any input field that is asking for a file path, it breaks the algorithm
                if input_field and input_field.get('type') != 'file':
                    form.set(name, "foobar<foobar")
                    response = browser_instance.submit_selected()
                    string = str(response.content)

                    # If we find the input character inside the response content, we know it didn't properly
                    # filter it out.
                    if string.find("foobar<foobar"):
                        san_num += 1
            except LinkNotFoundError:
                print("No form found.")

    return sql_injection_num, sensitive_data_leak_num, bad_response_num, dos_num, san_num


if __name__ == '__main__':
    set_arg()
