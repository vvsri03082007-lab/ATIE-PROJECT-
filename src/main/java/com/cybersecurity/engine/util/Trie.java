package com.cybersecurity.engine.util;

import com.cybersecurity.engine.model.ThreatCategory;
import java.util.HashMap;
import java.util.Map;

/**
 * Custom Trie (Prefix Tree) data structure for efficient keyword and prefix signature matching.
 */
// Concept: Class
public class Trie {

    private final TrieNode root;

    public Trie() {
        this.root = new TrieNode();
    }

    /**
     * Inserts a signature pattern and its associated ThreatCategory into the Trie.
     *
     * @param pattern  The signature string to insert.
     * @param category The category of threat this signature represents.
     */
    public void insert(String pattern, ThreatCategory category) {
        if (pattern == null || pattern.isEmpty()) {
            return;
        }
        TrieNode current = root;
        // Topic: Loops (for-each)
        for (char ch : pattern.toLowerCase().toCharArray()) {
            current = current.children.computeIfAbsent(ch, k -> new TrieNode());
        }
        current.isEndOfWord = true;
        current.category = category;
    }

    /**
     * Checks if a given text starts with any signature stored in the Trie.
     * Useful for checking path prefixes (e.g., checking if "/wp-admin/install.php" starts with "/wp-admin/").
     *
     * @param text The input string to check.
     * @return The matching ThreatCategory if a signature matches, null otherwise.
     */
    public ThreatCategory searchPrefixOf(String text) {
        if (text == null || text.isEmpty()) {
            return null;
        }
        TrieNode current = root;
        String lowerText = text.toLowerCase();
        // Topic: Loops (indexed for loop)
        for (int i = 0; i < lowerText.length(); i++) {
            char ch = lowerText.charAt(i);
            current = current.children.get(ch);
            if (current == null) {
                return null;
            }
            if (current.isEndOfWord) {
                return current.category;
            }
        }
        return null;
    }

    /**
     * Searches for any substring in the text that matches a prefix in the Trie.
     * This scans the text from every starting index.
     *
     * @param text The input text.
     * @return The matching ThreatCategory if any signature is found, null otherwise.
     */
    public ThreatCategory searchAnySubstringPrefix(String text) {
        if (text == null || text.isEmpty()) {
            return null;
        }
        String lowerText = text.toLowerCase();
        // Topic: Loops (nested loops for substring scan)
        for (int i = 0; i < lowerText.length(); i++) {
            // Check if there is a prefix match starting at index i
            TrieNode current = root;
            // Topic: Loops
            for (int j = i; j < lowerText.length(); j++) {
                char ch = lowerText.charAt(j);
                current = current.children.get(ch);
                if (current == null) {
                    break;
                }
                if (current.isEndOfWord) {
                    return current.category;
                }
            }
        }
        return null;
    }
}
