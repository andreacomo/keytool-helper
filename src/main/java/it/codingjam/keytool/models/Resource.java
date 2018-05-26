package it.codingjam.keytool.models;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;

/**
 * Helper class for loading resources (either from <strong>file</strong> or <strong>classpath</strong>)
 *
 * <br>
 * Created by acomo on 08/05/17.
 */
public class Resource {

    private static final String CLASSPATH_PREFIX = "classpath:";

    private String ref;

    private Resource(String ref) {
        this.ref = ref;
    }

    public static Resource from(String ref) {
        return new Resource(ref);
    }

    public InputStream getInputStream() throws FileNotFoundException {
        if (ref.startsWith(CLASSPATH_PREFIX)) {
            String classPathResource = ref.replace("classpath:", "");
            return this.getClass().getClassLoader().getResourceAsStream(classPathResource);
        } else {
            return new FileInputStream(ref);
        }
    }
}
