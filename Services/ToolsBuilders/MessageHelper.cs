 namespace NetworkMonitor.LLM.Services.Objects;
public class MessageHelper {
    public static string ErrorMessage(string message)
    {
        return "</llm-error>" + message;
                
    }
     public static string SuccessMessage(string message)
    {
        return "</llm-success>" + message;
                
    }
    public static string WarningMessage(string message)
    {
        return "</llm-warning>" + message;
                
    }
      public static string InfoMessage(string message)
    {
        return "</llm-info>" + message;
                
    }
 }
 