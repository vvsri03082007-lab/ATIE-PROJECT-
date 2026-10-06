package com.cybersecurity.engine.util;

import java.util.HashMap;
import java.util.Map;

/**
 * Custom implementation of the Boyer-Moore String Matching algorithm.
 * Uses the Bad Character heuristic for efficient substring pattern matching.
 */
// Concept: Class
public class BoyerMooreMatcher {
    private final String pattern;
    private final Map<Character, Integer> badCharMap;

    /**
     * Constructs a Boyer-Moore matcher for a given pattern.
     * Preprocesses the pattern to build the Bad Character shift table.
     *
     * @param pattern The pattern string to match.
     */
    // Concept: Constructor
    public BoyerMooreMatcher(String pattern) {
        this.pattern = pattern.toLowerCase();
        this.badCharMap = new HashMap<>();
        preprocessBadCharacter();
    }

    /**
     * Precomputes the last occurrence index of each character in the pattern.
     */
    private void preprocessBadCharacter() {
        int m = pattern.length();
        // Topic: Loops
        for (int i = 0; i < m; i++) {
            badCharMap.put(pattern.charAt(i), i);
        }
    }

    /**
     * Searches for the pattern within the given text using Boyer-Moore heuristics.
     * Matches are case-insensitive.
     *
     * @param text The source text to search in.
     * @return The starting index of the first match, or -1 if no match is found.
     */
    // Concept: Methods
    public int search(String text) {
        if (text == null || pattern == null) {
            return -1;
        }

        String lowerText = text.toLowerCase();
        int n = lowerText.length();
        int m = pattern.length();

        if (m == 0) {
            return 0; // Empty pattern matches instantly at start
        }
        if (n < m) {
            return -1; // Text is shorter than pattern
        }

        int shift = 0;
        // Topic: Loops
        while (shift <= (n - m)) {
            int j = m - 1;

            // Align pattern and text, match from right to left
            // Topic: Loops
            while (j >= 0 && pattern.charAt(j) == lowerText.charAt(shift + j)) {
                j--;
            }

            if (j < 0) {
                // Match found! Return the starting index
                return shift;
            } else {
                // Character mismatch in text at index (shift + j)
                char mismatchedChar = lowerText.charAt(shift + j);
                int lastOccur = badCharMap.getOrDefault(mismatchedChar, -1);

                // Shift pattern based on bad character heuristic
                // If character is not in pattern, shift pattern past mismatched character
                // Otherwise, align last occurrence of character with mismatched character
                int badCharShift = j - lastOccur;
                shift += Math.max(1, badCharShift);
            }
        }
        return -1;
    }
}
