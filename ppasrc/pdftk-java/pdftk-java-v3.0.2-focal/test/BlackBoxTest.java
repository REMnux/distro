import static org.junit.Assert.assertEquals;
import org.junit.Rule;
import org.junit.Test;
import org.junit.contrib.java.lang.system.SystemOutRule;
import org.junit.contrib.java.lang.system.ExpectedSystemExit;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.io.IOException;

import com.gitlab.pdftk_java.pdftk;

public class BlackBoxTest {
  @Rule
  public final SystemOutRule systemOutRule =
    new SystemOutRule().muteForSuccessfulTests();

  @Rule
  public final ExpectedSystemExit exit = ExpectedSystemExit.none();

  public String slurp(String filename) throws IOException {
    return new String(slurpBytes(filename));
  }
  public byte[] slurpBytes(String filename) throws IOException {
    return Files.readAllBytes(Paths.get(filename));
  }
  
  @Test
  public void dump_data() throws IOException {
    exit.expectSystemExitWithStatus(0);
    pdftk.main(new String[]{"test/files/blank.pdf", "dump_data_utf8"});
    String expectedData = slurp("test/files/blank.data");
    assertEquals(expectedData, systemOutRule.getLog());    
  }

  @Test
  public void cat() throws IOException {
    exit.expectSystemExitWithStatus(0);
    pdftk.main(new String[]{"test/files/refs.pdf",
                            "test/files/refsalt.pdf",
                            "cat", "output", "-"});
    byte[] expectedData = slurpBytes("test/files/cat-refs-refsalt.pdf");
    assertEquals(expectedData, systemOutRule.getLogAsBytes());
  }

  @Test
  public void cat_rotate_page_no_op() throws IOException {
    exit.expectSystemExitWithStatus(0);
    pdftk.main(new String[]{"test/files/blank.pdf",
                            "cat", "1north", "output", "-"});
    byte[] expectedData = slurpBytes("test/files/blank.pdf");
    assertEquals(expectedData, systemOutRule.getLogAsBytes());
  }

  @Test
  public void cat_rotate_range_no_op() throws IOException {
    exit.expectSystemExitWithStatus(0);
    pdftk.main(new String[]{"test/files/blank.pdf",
                            "cat", "1-1north", "output", "-"});
    byte[] expectedData = slurpBytes("test/files/blank.pdf");
    assertEquals(expectedData, systemOutRule.getLogAsBytes());
  }

  @Test
  public void cat_rotate_page() throws IOException {
    exit.expectSystemExitWithStatus(0);
    pdftk.main(new String[]{"test/files/blank.pdf",
                            "cat", "1east", "output", "-"});
    byte[] expectedData = slurpBytes("test/files/blank.pdf");
    assertEquals(expectedData, systemOutRule.getLogAsBytes());
  }

  @Test
  public void cat_rotate_range() throws IOException {
    exit.expectSystemExitWithStatus(0);
    pdftk.main(new String[]{"test/files/blank.pdf",
                            "cat", "1-1east", "output", "-"});
    byte[] expectedData = slurpBytes("test/files/blank.pdf");
    assertEquals(expectedData, systemOutRule.getLogAsBytes());
  }

};
