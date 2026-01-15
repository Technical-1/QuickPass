//! Entropy collection via mini-games.
//!
//! This module provides a simple Tic-Tac-Toe game that collects user interaction
//! data (clicks, timestamps, move sequences) to generate additional entropy
//! for password generation.

use sha2::{Digest, Sha256};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// Tic-Tac-Toe game state for entropy collection
#[derive(Clone, Debug)]
pub struct TicTacToe {
    /// 3x3 board: None = empty, Some(true) = X, Some(false) = O
    pub board: [[Option<bool>; 3]; 3],
    /// Current player: true = X (human), false = O (computer)
    pub current_player: bool,
    /// Entropy pool from user interactions
    entropy_data: Vec<u8>,
    /// Start time for timing-based entropy
    start_time: Instant,
    /// Move count
    pub move_count: u32,
    /// Game over flag
    pub game_over: bool,
    /// Winner: None = draw/ongoing, Some(true) = X wins, Some(false) = O wins
    pub winner: Option<bool>,
}

impl Default for TicTacToe {
    fn default() -> Self {
        Self::new()
    }
}

impl TicTacToe {
    pub fn new() -> Self {
        // Seed entropy with system time
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let mut entropy_data = Vec::new();
        entropy_data.extend_from_slice(&now.as_nanos().to_le_bytes());

        Self {
            board: [[None; 3]; 3],
            current_player: true, // X starts
            entropy_data,
            start_time: Instant::now(),
            move_count: 0,
            game_over: false,
            winner: None,
        }
    }

    /// Make a move at the given position, collecting entropy from the interaction
    pub fn make_move(&mut self, row: usize, col: usize) -> bool {
        if self.game_over || row >= 3 || col >= 3 || self.board[row][col].is_some() {
            return false;
        }

        // Collect entropy from this move
        self.collect_entropy(row, col);

        // Place the move
        self.board[row][col] = Some(self.current_player);
        self.move_count += 1;

        // Check for winner
        if let Some(winner) = self.check_winner() {
            self.game_over = true;
            self.winner = Some(winner);
            return true;
        }

        // Check for draw
        if self.is_board_full() {
            self.game_over = true;
            self.winner = None;
            return true;
        }

        // Switch player
        self.current_player = !self.current_player;

        // If it's computer's turn, make a move
        if !self.current_player {
            self.computer_move();
        }

        true
    }

    /// Collect entropy from user interaction
    fn collect_entropy(&mut self, row: usize, col: usize) {
        // Add position data
        self.entropy_data.push(row as u8);
        self.entropy_data.push(col as u8);

        // Add timing data (microseconds since game start)
        let elapsed = self.start_time.elapsed().as_micros();
        self.entropy_data.extend_from_slice(&elapsed.to_le_bytes());

        // Add move count
        self.entropy_data.extend_from_slice(&self.move_count.to_le_bytes());

        // Add current system time for additional randomness
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        self.entropy_data.extend_from_slice(&now.as_nanos().to_le_bytes());
    }

    /// Simple computer AI - tries to win, block, or pick random
    fn computer_move(&mut self) {
        if self.game_over {
            return;
        }

        // Try to win
        if let Some((r, c)) = self.find_winning_move(false) {
            self.board[r][c] = Some(false);
            self.move_count += 1;
            if self.check_winner().is_some() {
                self.game_over = true;
                self.winner = Some(false);
            }
            self.current_player = true;
            return;
        }

        // Try to block
        if let Some((r, c)) = self.find_winning_move(true) {
            self.board[r][c] = Some(false);
            self.move_count += 1;
            self.current_player = true;
            return;
        }

        // Take center if available
        if self.board[1][1].is_none() {
            self.board[1][1] = Some(false);
            self.move_count += 1;
            self.current_player = true;
            return;
        }

        // Take any available corner
        for (r, c) in [(0, 0), (0, 2), (2, 0), (2, 2)] {
            if self.board[r][c].is_none() {
                self.board[r][c] = Some(false);
                self.move_count += 1;
                self.current_player = true;
                return;
            }
        }

        // Take any available edge
        for (r, c) in [(0, 1), (1, 0), (1, 2), (2, 1)] {
            if self.board[r][c].is_none() {
                self.board[r][c] = Some(false);
                self.move_count += 1;
                self.current_player = true;
                return;
            }
        }

        // Check for draw
        if self.is_board_full() {
            self.game_over = true;
        }
    }

    /// Find a winning move for the given player
    fn find_winning_move(&self, player: bool) -> Option<(usize, usize)> {
        for r in 0..3 {
            for c in 0..3 {
                if self.board[r][c].is_none() {
                    let mut test_board = self.board;
                    test_board[r][c] = Some(player);
                    if Self::check_winner_board(&test_board) == Some(player) {
                        return Some((r, c));
                    }
                }
            }
        }
        None
    }

    /// Check if there's a winner
    fn check_winner(&self) -> Option<bool> {
        Self::check_winner_board(&self.board)
    }

    fn check_winner_board(board: &[[Option<bool>; 3]; 3]) -> Option<bool> {
        // Check rows
        for row in board {
            if row[0].is_some() && row[0] == row[1] && row[1] == row[2] {
                return row[0];
            }
        }

        // Check columns
        for c in 0..3 {
            if board[0][c].is_some() && board[0][c] == board[1][c] && board[1][c] == board[2][c] {
                return board[0][c];
            }
        }

        // Check diagonals
        if board[0][0].is_some() && board[0][0] == board[1][1] && board[1][1] == board[2][2] {
            return board[0][0];
        }
        if board[0][2].is_some() && board[0][2] == board[1][1] && board[1][1] == board[2][0] {
            return board[0][2];
        }

        None
    }

    fn is_board_full(&self) -> bool {
        self.board.iter().all(|row| row.iter().all(|cell| cell.is_some()))
    }

    /// Get the collected entropy as a SHA-256 hash (32 bytes)
    pub fn get_entropy(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&self.entropy_data);
        hasher.finalize().into()
    }

    /// Get entropy as a hex string for display
    pub fn get_entropy_hex(&self) -> String {
        let hash = self.get_entropy();
        hash.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// Reset the game for another round (accumulates more entropy)
    pub fn reset(&mut self) {
        // Keep existing entropy and add more from the reset action
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        self.entropy_data.extend_from_slice(&now.as_nanos().to_le_bytes());

        self.board = [[None; 3]; 3];
        self.current_player = true;
        self.start_time = Instant::now();
        self.move_count = 0;
        self.game_over = false;
        self.winner = None;
    }

    /// Get the symbol for a cell
    pub fn cell_symbol(&self, row: usize, col: usize) -> &'static str {
        match self.board[row][col] {
            Some(true) => "X",
            Some(false) => "O",
            None => "",
        }
    }

    /// Check if a cell is clickable
    pub fn is_cell_clickable(&self, row: usize, col: usize) -> bool {
        !self.game_over && self.current_player && self.board[row][col].is_none()
    }

    /// Get status message
    pub fn status_message(&self) -> &'static str {
        if self.game_over {
            match self.winner {
                Some(true) => "You win!",
                Some(false) => "Computer wins!",
                None => "It's a draw!",
            }
        } else if self.current_player {
            "Your turn (X)"
        } else {
            "Computer thinking..."
        }
    }
}

/// Mix game entropy with system RNG for password generation
pub fn mix_entropy_with_rng(game_entropy: &[u8; 32], rng_bytes: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(game_entropy);
    hasher.update(rng_bytes);

    // Add current time
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    hasher.update(&now.as_nanos().to_le_bytes());

    hasher.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_game() {
        let game = TicTacToe::new();
        assert!(!game.game_over);
        assert!(game.current_player);
        assert_eq!(game.move_count, 0);
    }

    #[test]
    fn test_make_move() {
        let mut game = TicTacToe::new();
        assert!(game.make_move(0, 0));
        assert!(game.board[0][0] == Some(true));
        // Computer should have moved
        assert!(game.current_player); // Back to player's turn
    }

    #[test]
    fn test_invalid_move() {
        let mut game = TicTacToe::new();
        game.make_move(0, 0);
        // Try to move to same spot
        let computer_moved = game.board.iter().flatten().filter(|c| c.is_some()).count() > 1;
        if computer_moved {
            // Computer already moved somewhere
            assert!(!game.make_move(0, 0)); // Can't move to X's spot
        }
    }

    #[test]
    fn test_entropy_collection() {
        let mut game = TicTacToe::new();
        let initial_len = game.entropy_data.len();
        game.make_move(0, 0);
        assert!(game.entropy_data.len() > initial_len);
    }

    #[test]
    fn test_entropy_uniqueness() {
        let mut game1 = TicTacToe::new();
        let mut game2 = TicTacToe::new();

        game1.make_move(0, 0);
        std::thread::sleep(std::time::Duration::from_millis(1));
        game2.make_move(0, 0);

        // Different timing should produce different entropy
        assert_ne!(game1.get_entropy(), game2.get_entropy());
    }

    #[test]
    fn test_reset_accumulates_entropy() {
        let mut game = TicTacToe::new();
        game.make_move(0, 0);
        let len_before = game.entropy_data.len();
        game.reset();
        assert!(game.entropy_data.len() > len_before);
        assert!(!game.game_over);
    }
}
