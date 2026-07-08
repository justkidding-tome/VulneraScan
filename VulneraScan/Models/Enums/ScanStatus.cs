namespace VulneraScan.Models.Enums
{
    /// <summary>
    /// Represents the current status of a scan operation.
    /// </summary>
    public enum ScanStatus
    {
        Pending = 0,
        InProgress = 1,
        Completed = 2,
        Failed = 3
    }
}
