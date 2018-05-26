package it.cosenonjaviste.keytool.utils;

/**
 * Helper preconditions checks
 *
 * Created by acomo on 08/05/17.
 */
public class Preconditions {

    private Preconditions() {
        // prevent instance
    }

    public static void checkState(boolean expression, String message) {
        if (!expression) {
            throw new IllegalStateException(message);
        }
    }

    public static void checkArgument(boolean expression, String message) {
        if (!expression) {
            throw new IllegalArgumentException(message);
        }
    }
}
