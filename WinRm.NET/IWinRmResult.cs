namespace WinRm.NET
{
    /// <summary>
    /// Represents the result of a WinRM command execution.
    /// </summary>
    public interface IWinRmResult
    {
        /// <summary>
        /// Gets a value indicating whether the command was successful.
        /// </summary>
        public bool IsSuccess { get; }

        /// <summary>
        /// Gets the standard output of the command
        /// </summary>
        public string Output { get; }

        /// <summary>
        /// Gets the standard error of the command
        /// </summary>
        public string Error { get; }

        /// <summary>
        /// Gets the error message if the command failed. (IsSuccess == false)
        /// </summary>
        public string ErrorMessage { get; }
    }
}
