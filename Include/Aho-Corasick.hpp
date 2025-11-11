#include <map>
#include <vector>
#include <string>
#include <queue>

using namespace std;

class TrieNode
{
public:
	map<char, TrieNode*> children;
	TrieNode* failLink = nullptr;
	vector<string> endsIn;
};

void insert(TrieNode* root, const vector<string>& words)
{
	for (string word : words)
	{
		TrieNode* currNode = root;
		for (char c : word)
		{
			if (currNode->children.find(c) == currNode->children.end())
			{
				currNode->children[c] = new TrieNode();
			}
			currNode = currNode->children[c];
		}
		currNode->endsIn.push_back(word);
	}
}

void buildFailLinks(TrieNode* root)
{
	queue<TrieNode*> bfs;
	for (auto& [c, child] : root->children)
	{
		child->failLink = root;
		bfs.push(child);
	}

	while (!bfs.empty())
	{
		TrieNode* currNode = bfs.front();
		bfs.pop();

		for (auto& [c, child] : currNode->children)
		{
			bfs.push(child);
			TrieNode* failNode = child->failLink;
			while (failNode != nullptr && failNode->children.find(c) == failNode->children.end())
			{
				failNode = failNode->failLink;
			}
			if (failNode == nullptr)
			{
				currNode->failLink = root;
			}
			else
			{
				currNode->failLink = failNode->children[c];
			}

			currNode->endsIn.insert(currNode->endsIn.end(), currNode->failLink->endsIn.begin(), currNode->failLink->endsIn.end());
		}
	}
}

map<string, int> search(TrieNode* root, const string& text)
{
	map<string, int> matches;
	TrieNode* currNode = root;

	for (char c : text)
	{
		while (currNode != nullptr && currNode->children.find(c) == currNode->children.end())
		{
			currNode = currNode->failLink;
		}

		if (currNode == nullptr)
		{
			currNode = root;
			continue;
		}

		currNode = currNode->children[c];

		if (!currNode->endsIn.empty())
		{
			for (string& word : currNode->endsIn)
			{
				matches[word]++;
			}
		}
	}

	return matches;
}