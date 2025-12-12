import customtkinter as ctk
from config import APPEARANCE_MODE, COLOR_THEME
from app import App


def main():
    """Initialize and run the application"""
    ctk.set_appearance_mode(APPEARANCE_MODE)
    ctk.set_default_color_theme(COLOR_THEME)
    
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()