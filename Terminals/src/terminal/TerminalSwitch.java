package terminal;

public interface TerminalSwitch {
    public void switchTerminal(byte t);
    public byte[] revokeCard(byte[] cardID);
    public boolean isRevokedCard(byte[] cardID);
}