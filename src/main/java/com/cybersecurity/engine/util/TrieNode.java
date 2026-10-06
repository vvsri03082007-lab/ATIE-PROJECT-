package com.cybersecurity.engine.util;

import com.cybersecurity.engine.model.ThreatCategory;
import java.util.HashMap;
import java.util.Map;

/**
 * Node structure for the custom Trie (Prefix Tree).
 * Used for prefix-based URL and directory path threat signature matching.
 */
// Concept: Class
public class TrieNode {
    // Package-private access to avoid boilerplate getter/setters for package classes
    final Map<Character, TrieNode> children = new HashMap<>();
    boolean isEndOfWord = false;
    ThreatCategory category = null;
}
