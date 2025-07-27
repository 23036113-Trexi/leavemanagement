# Leave Request Form Implementation Plan

## Overview
This document outlines the implementation plan for the core functionality of submitting leave requests through a web form in the GeoLah Leave Management System.

## Current System Analysis
- **Backend**: Express.js server with MySQL database connection
- **Frontend**: EJS templating engine
- **Database**: MySQL with predefined schema for leave management
- **Dependencies**: express, mysql2, ejs

## Implementation Components

### 1. Database Preparation
- **Status**: Ready (schema already defined in CLAUDE.md)
- **Tables Used**:
  - `leave_request` - Store leave request data
  - `leave_type` - Reference leave types (Annual, Medical, Other)
  - `users` - User authentication and role management
  - `leave_balance` - Track remaining leave balances

### 2. Backend API Endpoints

#### 2.1 GET /leave-request-form
- **Purpose**: Serve the leave request form page
- **Requirements**:
  - Render EJS template with form
  - Fetch available leave types from database
  - Include user session validation
  - Pre-populate user information

#### 2.2 POST /submit-leave-request
- **Purpose**: Process leave request submission
- **Requirements**:
  - Validate form data
  - Calculate number of days (including half-day logic)
  - Insert into `leave_request` table
  - Update leave balances
  - Return success/error response

#### 2.3 GET /leave-types
- **Purpose**: API endpoint to fetch available leave types
- **Requirements**:
  - Query `leave_type` table
  - Return JSON response

### 3. Frontend Components

#### 3.1 Leave Request Form (leave-request.ejs)
- **Form Fields**:
  - Leave Type (dropdown from database)
  - Start Date (date picker)
  - End Date (date picker) 
  - Half Day option (radio buttons: None, AM, PM)
  - Reason (textarea)
  - Auto-calculated: Number of days, Request date, User ID

#### 3.2 Form Validation
- **Client-side**:
  - Required field validation
  - Date range validation (end date >= start date)
  - Future date validation
  - Reason character limit
- **Server-side**:
  - Data sanitization
  - Business logic validation
  - Leave balance verification

#### 3.3 User Interface Elements
- **Styling**: CSS for professional form appearance
- **JavaScript**: Form interactivity and date calculations
- **Feedback**: Success/error messages

### 4. Business Logic Implementation

#### 4.1 Leave Day Calculation
- **Full Days**: Calculate working days between start and end dates
- **Half Days**: 0.5 days for AM/PM options
- **Weekend Handling**: Exclude weekends from calculations
- **Holiday Handling**: Future enhancement

#### 4.2 Leave Balance Validation
- Check sufficient balance before allowing submission
- Different balance types for different leave types:
  - Annual Leave → `annual_leave_balance`
  - Medical Leave → `medical_leave_balance`
  - Other Leave → `other_leave_balance`

#### 4.3 Data Integrity
- Transaction-based operations for balance updates
- Proper error handling and rollback mechanisms
- Input sanitization to prevent SQL injection

### 5. File Structure

```
/views/
  ├── leave-request.ejs          # Leave request form page
  ├── partials/
      ├── header.ejs             # Common header
      └── footer.ejs             # Common footer

/public/
  ├── css/
      └── leave-request.css      # Form styling
  ├── js/
      └── leave-request.js       # Form interactivity

/routes/ (to be created)
  └── leave-routes.js            # Leave-related API endpoints

/middleware/ (to be created)
  └── auth.js                    # Authentication middleware
```

### 6. Implementation Phases

#### Phase 1: Basic Form Structure
1. Create EJS template for leave request form
2. Set up basic Express routes
3. Implement form rendering with static data

#### Phase 2: Database Integration
1. Create API endpoints for leave types
2. Implement form submission handler
3. Add database insert operations

#### Phase 3: Business Logic
1. Implement leave day calculation
2. Add leave balance validation
3. Implement proper error handling

#### Phase 4: User Experience
1. Add client-side validation
2. Implement form styling
3. Add success/error feedback

#### Phase 5: Security & Validation
1. Add authentication middleware
2. Implement server-side validation
3. Add input sanitization

### 7. Technical Considerations

#### 7.1 Security
- Input validation and sanitization
- SQL injection prevention
- Authentication middleware
- CSRF protection

#### 7.2 Error Handling
- Database connection errors
- Validation errors
- Business logic errors
- User-friendly error messages

#### 7.3 Performance
- Database query optimization
- Form submission feedback
- Client-side validation for better UX

### 8. Testing Strategy
- Unit tests for business logic functions
- Integration tests for API endpoints
- Form validation testing
- Database transaction testing

### 9. Future Enhancements
- Email notifications to managers
- Leave request status tracking
- Calendar integration
- Mobile responsiveness
- File attachments for medical leave

## Success Criteria
- ✅ Users can access leave request form
- ✅ Form validates input properly
- ✅ Leave requests are stored in database
- ✅ Leave balances are updated correctly
- ✅ Appropriate error handling and user feedback
- ✅ Clean, professional user interface

## Dependencies & Prerequisites
- MySQL database with schema loaded
- Express.js server configured
- EJS templating engine set up
- User authentication system (future requirement)
- Session management (future requirement)