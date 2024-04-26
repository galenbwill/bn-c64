from collections import OrderedDict
import sys
import json
import argparse
import re
from wikitextparser import parse
from pathlib import Path


def merge_rows_with_blank_first_column(rows):
    merged_rows = []
    prev_row = None
    for row in rows:
        if row[0] == "" or prev_row is not None and row[0] == prev_row[0]:
            if prev_row is not None:
                prev_row[-1] += '\n' + row[-1]
        else:
            if prev_row is not None:
                merged_rows.append(prev_row)
            prev_row = row
    if prev_row is not None:
        merged_rows.append(prev_row)
    return merged_rows


def extract_start_and_length(entry):
    try:
        if '-' in entry:
            start, end = entry.split('-')
            start = int(start.strip())
            end = int(end.strip())
            return start, end - start + 1
        else:
            return int(entry.strip()), 1
    except Exception as e:
        print(f"Error: Failed to extract start and length from entry: {entry}")
        raise e


def wikitext_to_json(input_files, output_file=None, use_map=False):
    for input_file in input_files:
        try:
            # Read Wikitext from input file
            with open(input_file, 'r', encoding='utf-8') as f:
                wikitext = f.read()

            # Remove "[[" and "]]" from the input text
            # wikitext = wikitext.replace("[[", "").replace("]]", "")

            # Parse Wikitext
            parsed = parse(wikitext)

            # Extract tables and convert to JSON
            tables = []
            for table in parsed.tables:
                if use_map:
                    table_data = OrderedDict()
                else:
                    table_data = []
                rows = table.data()
                columns = [cell.strip() for cell in rows[0]]

                def delink(x):
                    # print(re.sub(r"\[\[(?:.*?\|?)(.*?)\]\]", r"\1", x.strip()))
                    sub = re.sub(r"\[\[(?:[^|\]]*\|)?([^|\]]*)\]\]", r"\1", x.strip())
                    # sub = re.sub(r"\[\[((?:[^|]*\|)([^|\]]*))?|([^|\]]*)\]\]", r"\1\2", x.strip())
                    print(sub)
                    return sub

                rows = list(map(lambda r: list(map(delink, r)), rows))
                rows = merge_rows_with_blank_first_column(rows[1:])
                for row in rows:
                    # row[-1] = row[-1].replace("[[", "").replace("]]", "")
                    if use_map:
                        key = row[1]
                        length = 1
                        try:
                            key, length = extract_start_and_length(row[1])
                        except Exception:
                            pass
                        row_data = {columns[i]: val for i, val in enumerate(row)}
                        row_data["length"] = length
                        table_data[key] = row_data
                    else:
                        table_data.append(dict(zip(columns, row)))
                tables.append(table_data)
            if len(tables) == 1:
                tables = tables[0]

            # Write JSON to file
            if output_file or len(input_files) > 1:
                output_filename = output_file if len(input_files) == 1 else Path(input_file).with_suffix('.json')
                with open(output_filename, 'w', encoding='utf-8') as f:
                    json.dump(tables, f, ensure_ascii=False, indent=4)
                print(f"JSON data written to '{output_filename}'")
            else:
                print(f"No output filename specified for '{input_file}', skipping JSON output.")
        except Exception as e:
            print(f"Error processing file: {input_file}")
            raise e


def main():
    parser = argparse.ArgumentParser(description="Convert Wikitext tables to JSON")
    parser.add_argument('input_files', nargs='+', help="Input files containing Wikitext")
    parser.add_argument('-o', '--output', help="Output JSON file (optional)")
    parser.add_argument('-m', '--map', action='store_true', help="Convert table rows into a map")
    args = parser.parse_args()

    wikitext_to_json(args.input_files, args.output, args.map)


if __name__ == "__main__":
    main()
