/**
 * Comprehensive JavaScript Error Prevention Utility
 * Prevents DOM access errors and provides safe methods for element manipulation
 */

// Global utility object for safe DOM operations
window.SafeDOM = {
  /**
   * Safely get an element by ID with null check
   * @param {string} id - Element ID
   * @returns {Element|null} - Element or null if not found
   */
  getElementById: function (id) {
    try {
      return document.getElementById(id);
    } catch (e) {
      console.warn(`Element with ID '${id}' not found:`, e);
      return null;
    }
  },

  /**
   * Safely query selector with null check
   * @param {string} selector - CSS selector
   * @returns {Element|null} - Element or null if not found
   */
  querySelector: function (selector) {
    try {
      return document.querySelector(selector);
    } catch (e) {
      console.warn(`Element with selector '${selector}' not found:`, e);
      return null;
    }
  },

  /**
   * Safely query all selectors with null check
   * @param {string} selector - CSS selector
   * @returns {NodeList|Array} - NodeList or empty array if not found
   */
  querySelectorAll: function (selector) {
    try {
      const elements = document.querySelectorAll(selector);
      return elements.length > 0 ? elements : [];
    } catch (e) {
      console.warn(`Elements with selector '${selector}' not found:`, e);
      return [];
    }
  },

  /**
   * Safely add event listener with element existence check
   * @param {string} selector - CSS selector or element ID
   * @param {string} event - Event type
   * @param {Function} handler - Event handler function
   * @param {boolean} isId - Whether selector is an ID (default: false)
   */
  addEventListenerSafe: function (selector, event, handler, isId = false) {
    try {
      const element = isId
        ? this.getElementById(selector)
        : this.querySelector(selector);
      if (element && typeof handler === "function") {
        element.addEventListener(event, handler);
        return true;
      } else {
        if (!element) {
          console.warn(
            `Cannot add event listener: Element '${selector}' not found`
          );
        } else {
          console.warn(`Cannot add event listener: Handler is not a function`);
        }
        return false;
      }
    } catch (e) {
      console.error(`Error adding event listener to '${selector}':`, e);
      return false;
    }
  },

  /**
   * Safely add event listeners to multiple elements
   * @param {string} selector - CSS selector
   * @param {string} event - Event type
   * @param {Function} handler - Event handler function
   */
  addEventListenersToAll: function (selector, event, handler) {
    try {
      const elements = this.querySelectorAll(selector);
      let count = 0;
      elements.forEach((element) => {
        if (element && typeof handler === "function") {
          element.addEventListener(event, handler);
          count++;
        }
      });
      return count;
    } catch (e) {
      console.error(`Error adding event listeners to '${selector}':`, e);
      return 0;
    }
  },

  /**
   * Wait for DOM to be ready and execute callback safely
   * @param {Function} callback - Function to execute when DOM is ready
   */
  ready: function (callback) {
    if (typeof callback !== "function") {
      console.warn("SafeDOM.ready: Callback must be a function");
      return;
    }

    try {
      if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", callback);
      } else {
        callback();
      }
    } catch (e) {
      console.error("Error in SafeDOM.ready:", e);
    }
  },

  /**
   * Safely set innerHTML with sanitization
   * @param {string} selector - CSS selector or element ID
   * @param {string} content - HTML content to set
   * @param {boolean} isId - Whether selector is an ID (default: false)
   */
  setInnerHTMLSafe: function (selector, content, isId = false) {
    try {
      const element = isId
        ? this.getElementById(selector)
        : this.querySelector(selector);
      if (element) {
        // Basic XSS prevention
        const sanitizedContent = content.replace(
          /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
          ""
        );
        element.innerHTML = sanitizedContent;
        return true;
      } else {
        console.warn(`Cannot set innerHTML: Element '${selector}' not found`);
        return false;
      }
    } catch (e) {
      console.error(`Error setting innerHTML for '${selector}':`, e);
      return false;
    }
  },

  /**
   * Safely toggle class with element existence check
   * @param {string} selector - CSS selector or element ID
   * @param {string} className - Class name to toggle
   * @param {boolean} isId - Whether selector is an ID (default: false)
   */
  toggleClassSafe: function (selector, className, isId = false) {
    try {
      const element = isId
        ? this.getElementById(selector)
        : this.querySelector(selector);
      if (element) {
        element.classList.toggle(className);
        return true;
      } else {
        console.warn(`Cannot toggle class: Element '${selector}' not found`);
        return false;
      }
    } catch (e) {
      console.error(`Error toggling class for '${selector}':`, e);
      return false;
    }
  },

  /**
   * Check if element exists
   * @param {string} selector - CSS selector or element ID
   * @param {boolean} isId - Whether selector is an ID (default: false)
   * @returns {boolean} - True if element exists
   */
  exists: function (selector, isId = false) {
    try {
      const element = isId
        ? this.getElementById(selector)
        : this.querySelector(selector);
      return element !== null;
    } catch (e) {
      console.warn(`Error checking existence of '${selector}':`, e);
      return false;
    }
  },
};

// Global error handler for unhandled JavaScript errors
window.addEventListener("error", function (e) {
  console.error("Global JavaScript Error:", {
    message: e.message,
    filename: e.filename,
    line: e.lineno,
    column: e.colno,
    error: e.error,
  });

  // Don't let the error break the entire page
  return true;
});

// Global handler for unhandled promise rejections
window.addEventListener("unhandledrejection", function (e) {
  console.error("Unhandled Promise Rejection:", e.reason);

  // Prevent the default handling (which would log to console)
  e.preventDefault();
});

// Console warning for common mistakes
console.log(
  "🛡️ JavaScript Error Prevention Utility Loaded - Use SafeDOM for safe DOM operations"
);

// Backward compatibility wrapper for common operations
window.safeGetElementById = function (id) {
  return SafeDOM.getElementById(id);
};

window.safeAddEventListener = function (
  selector,
  event,
  handler,
  isId = false
) {
  return SafeDOM.addEventListenerSafe(selector, event, handler, isId);
};

window.safeReady = function (callback) {
  return SafeDOM.ready(callback);
};
