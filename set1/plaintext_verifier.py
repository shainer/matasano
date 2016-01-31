import collections

class PlaintextVerifier(object):
	def __init__(self):
		pass

	def _MatchedParentheses(self, s):
		"""Checks whether open parentheses and quotes are always closed."""
		braces = 0
		brackets = 0
		regulars = 0
		quotes = 0

		for ch in s:
			if ch == '{':
				braces += 1
			elif ch == '}':
				braces -= 1

			elif ch == '[':
				brackets += 1
			elif ch == ']':
				brackets -= 1
			
			elif ch == '(':
				regulars += 1
			elif ch == ')':
				regulars -= 1
			elif ch == "\"":
				quotes += 1

		return ((braces == 0) and
				(brackets == 0) and
				(regulars == 0) and
				(quotes % 2 == 0))


	def _FollowedBySpace(self, s, ch):
		try:
			i = s.index(ch)
			return (i == len(s) - 1 or s[i + 1] == ' ')
		except ValueError:
			# Trivial case: the character is not in the string.
			return True


	def _CheckPunctuaction(self, s):
		"""Checks whether some punctuaction characters are always
		followed by a whitespace, unless they are at the end."""
		return (self._FollowedBySpace(s, '!') and
				self._FollowedBySpace(s, '?') and
				self._FollowedBySpace(s, '.'))

	def _SortByFrequency(self, s):
		"""Returns a list of characters in s, sorted by their frequency in it."""
		# Builds a frequency map (mapping between char and number of
		# occurrences).
		freq_map = collections.defaultdict(int)

		for ch in s:
			freq_map[ch] += 1

		# Sort the map keys by their value, in reverse order, so the most
		# common character is first in the list.
		return sorted(freq_map.keys(),
				  	  key = lambda x : freq_map[x],
				  	  reverse=True)

	def _CheckFrequency(self, s):
		"""Checks whether the most frequent character in the text is in the list
		of most frequent characters in English text."""
		freq_list = self._SortByFrequency(s)
		return (freq_list[0] in 'ETAOIN ')

	def IsEnglishPlaintext(self, s, check_frequency=True):
		# Text starts with a capital letter.
		if s[0] < 'A' or s[0] > 'Z':
			return False

		if not self._MatchedParentheses(s):
			return False

		if not self._CheckPunctuaction(s):
			return False

		if check_frequency and not self._CheckFrequency(s):
			return False

		return True