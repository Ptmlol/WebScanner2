# [[a,b], [b,c], [a,d], [a,g], [g,h], [b,j]]
import json

def generate_tree(list):
    try:
        node_dict = {}
        tree = {'name': 'root', 'children': []}
        for pair in list:
            if pair[0] not in node_dict:
                second_node = {'name': pair[1], 'children': []}
                node = {'name': pair[0], 'children': [second_node]}
                tree['children'].append(node)
                node_dict[pair[0]] = node
                node_dict[pair[1]] = second_node
            else:
                node = node_dict[pair[0]]
                second_node = {'name': pair[1], 'children': []} if pair[1] not in node_dict else node_dict[pair[1]]
                if pair[1] not in node_dict:
                    node_dict[pair[1]] = second_node
                node['children'].append(second_node)
        return json.dumps(tree)
    except Exception as e:
        print(e)


list = [['a', 'b'], ['b', 'c'], ['a', 'd'], ['a', 'g'], ['g', 'h'], ['b', 'j'], ['z', 'x']]
# print(generate_tree(list))
