package com.github.xingjianluo.localsupplychainauditjava.parse;

import com.github.xingjianluo.localsupplychainauditjava.model.ManifestInput;
import com.github.xingjianluo.localsupplychainauditjava.model.ManifestResult;

/**
 * Parses one manifest format. Implementations must never let a broken file escape
 * as an exception: every failure becomes a traceable CORRUPT/PARTIALLY_PARSED result.
 */
public interface ManifestParser {

    /** Whether this parser handles the given input. */
    boolean supports(ManifestInput input);

    /** Parse the input and always return a result carrying an explicit status. */
    ManifestResult parse(ManifestInput input);
}
